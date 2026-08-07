"""F114.A — Active Open Redirect Probe.

Sends a small, fixed set of crafted redirect payloads against the
target endpoint's URL parameter, observes Location header + body,
feeds the observation back to F103 `analyze_observations` for
classification.

Double-gate banca-safety:
  * `fire=True` config arg
  * `KRYON_OPENREDIRECT_FIRE=true` env var
Both required; without both, the call is a dry-run (no traffic,
payloads-only report)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse

import requests
from requests.adapters import HTTPAdapter

from kryon.tools.api.open_redirect import (
    RedirectFinding,
    RedirectObservation,
    analyze_observations,
)

__all__ = [
    "OpenRedirectActiveConfig",
    "OpenRedirectActiveResult",
    "ActiveProbeAttempt",
    "probe_open_redirect_active",
    "build_redirect_payloads",
]


_FIRE_ENV = "KRYON_OPENREDIRECT_FIRE"


def build_redirect_payloads(canary_host: str) -> tuple[str, ...]:
    """Return the canonical fixed payload set. Operator-overridable.

    Each payload exercises a different bypass class. Server should
    NEVER follow any of them; if it does, that confirms open
    redirect."""
    return (
        f"https://{canary_host}/kryon-redir-1",
        f"http://{canary_host}/kryon-redir-2",
        # Scheme-relative — interpreted as canary_host by browsers
        f"//{canary_host}/kryon-redir-3",
        # Userinfo bypass (legit-looking-prefix@attacker)
        f"https://example.com@{canary_host}/kryon-redir-4",
        # URL-encoded variant
        f"https%3A%2F%2F{canary_host}%2Fkryon-redir-5",
        # Whitespace prefix (some parsers strip)
        f" https://{canary_host}/kryon-redir-6",
        # Backslash variants (some servers normalize)
        f"\\\\{canary_host}/kryon-redir-7",
        # Double-encoded
        f"https%253A%252F%252F{canary_host}%252Fkryon-redir-8",
    )


@dataclass(frozen=True)
class OpenRedirectActiveConfig:
    """One target endpoint + the parameter to test."""

    endpoint_url: str  # e.g. "https://target.com/login?next=PLACEHOLDER&foo=bar"
    parameter_name: str  # e.g. "next"
    canary_host: str = "kryon-canary.invalid"  # safe non-resolving default
    payloads: tuple[str, ...] = ()  # override; empty = use build_redirect_payloads(canary_host)
    fire: bool = False  # MUST be True AND env-gate must pass to send traffic
    timeout_seconds: float = 5.0
    rate_limit_per_second: float = 5.0
    follow_redirects: bool = False  # Stay on the first redirect, that's the signal
    user_agent: str = "Kryon-OpenRedirect/1.0 (banca-safe; +read-only)"
    extra_headers: tuple[tuple[str, str], ...] = ()
    extra_cookies: tuple[tuple[str, str], ...] = ()
    max_body_bytes: int = 5_000


@dataclass(frozen=True)
class ActiveProbeAttempt:
    """One sent payload + its outcome."""

    payload: str
    request_url: str
    http_status: int
    response_location: str = ""
    response_body_snippet: str = ""
    elapsed_seconds: float = 0.0
    error: str = ""


@dataclass(frozen=True)
class OpenRedirectActiveResult:
    findings: tuple[RedirectFinding, ...] = field(default_factory=tuple)
    attempts: tuple[ActiveProbeAttempt, ...] = field(default_factory=tuple)
    payloads_built: tuple[str, ...] = field(default_factory=tuple)
    fired: bool = False
    fire_gate_state: str = ""  # debug: which gate blocked / passed
    elapsed_seconds: float = 0.0


def _env_fire_gate() -> bool:
    """Check the env-var half of the double-gate."""
    return os.environ.get(_FIRE_ENV, "").strip().lower() in ("true", "1", "yes")


def _build_probe_url(base: str, parameter_name: str, value: str) -> str:
    """Replace (or set) `parameter_name` in `base`'s query string
    with `value`, preserving other params."""
    parsed = urlparse(base)
    # Parse existing query as a list of pairs (preserving duplicates)
    pairs: list[tuple[str, str]] = []
    if parsed.query:
        for entry in parsed.query.split("&"):
            if "=" in entry:
                k, v = entry.split("=", 1)
                pairs.append((k, v))
            elif entry:
                pairs.append((entry, ""))
    # Replace existing value for parameter_name, or append
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
    # Reconstruct
    new_query = urlencode(out_pairs, safe=":/?#[]@!$&'()*+,;=")
    rebuilt = parsed._replace(query=new_query).geturl()
    return rebuilt


def probe_open_redirect_active(
    config: OpenRedirectActiveConfig,
) -> OpenRedirectActiveResult:
    """Execute the active probe. Returns dry-run result if either gate
    is missing."""
    t0 = time.monotonic()
    payloads = config.payloads or build_redirect_payloads(config.canary_host)

    # Double-gate
    if not config.fire:
        return OpenRedirectActiveResult(
            payloads_built=payloads,
            fired=False,
            fire_gate_state="config.fire=False",
            elapsed_seconds=time.monotonic() - t0,
        )
    if not _env_fire_gate():
        return OpenRedirectActiveResult(
            payloads_built=payloads,
            fired=False,
            fire_gate_state=f"env {_FIRE_ENV}!=true",
            elapsed_seconds=time.monotonic() - t0,
        )

    # Endpoint must be http(s)
    parsed = urlparse(config.endpoint_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return OpenRedirectActiveResult(
            payloads_built=payloads,
            fired=False,
            fire_gate_state=f"invalid endpoint_url scheme {parsed.scheme!r}",
            elapsed_seconds=time.monotonic() - t0,
        )

    # Session setup
    sess = requests.Session()
    sess.headers["User-Agent"] = config.user_agent
    for n, v in config.extra_headers:
        sess.headers[n] = v
    for n, v in config.extra_cookies:
        sess.cookies.set(n, v)
    adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    min_interval = 1.0 / config.rate_limit_per_second if config.rate_limit_per_second > 0 else 0.0
    last_fetch = 0.0
    attempts: list[ActiveProbeAttempt] = []
    observations: list[RedirectObservation] = []

    for payload in payloads:
        # Rate limit
        if min_interval > 0:
            wait = min_interval - (time.monotonic() - last_fetch)
            if wait > 0:
                time.sleep(wait)
        last_fetch = time.monotonic()

        probe_url = _build_probe_url(config.endpoint_url, config.parameter_name, payload)
        a_start = time.monotonic()
        try:
            resp = sess.get(
                probe_url,
                timeout=config.timeout_seconds,
                allow_redirects=config.follow_redirects,
                stream=True,
            )
            # Read body cap
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
            body = bytes(buf[: config.max_body_bytes]).decode(resp.encoding or "utf-8", errors="replace")
            location = resp.headers.get("Location", "") or ""
            elapsed = time.monotonic() - a_start
            attempts.append(
                ActiveProbeAttempt(
                    payload=payload,
                    request_url=probe_url,
                    http_status=resp.status_code,
                    response_location=location,
                    response_body_snippet=body[:500],
                    elapsed_seconds=elapsed,
                )
            )
            observations.append(
                RedirectObservation(
                    url=config.endpoint_url,
                    parameter_name=config.parameter_name,
                    probe_value=payload,
                    response_status=resp.status_code,
                    response_location_header=location,
                    response_body_snippet=body[:500],
                )
            )
        except (requests.exceptions.RequestException, OSError) as e:
            elapsed = time.monotonic() - a_start
            attempts.append(
                ActiveProbeAttempt(
                    payload=payload,
                    request_url=probe_url,
                    http_status=0,
                    elapsed_seconds=elapsed,
                    error=f"{type(e).__name__}: {e}",
                )
            )

    analysis = analyze_observations(observations)
    return OpenRedirectActiveResult(
        findings=analysis.findings,
        attempts=tuple(attempts),
        payloads_built=payloads,
        fired=True,
        fire_gate_state="both-gates-open",
        elapsed_seconds=time.monotonic() - t0,
    )
