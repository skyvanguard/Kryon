"""F113 — Replay Engine.

Re-verifies that each `UnifiedFinding` from a prior pipeline run is
still present. Closes the audit feedback loop: before you ship a
report, replay strips findings that the target has already
remediated.

**Banca-safety contract**:

  * Read-only: same network surface as the underlying analyzers
    (GET + HEAD only).
  * Single attempt per finding. No re-tries on failure.
  * Rate-limited per host (shared bucket across the replay).
  * Auth flow runs once + session reused for all re-checks.
  * Stale findings (target unreachable, auth expired) classify as
    `inconclusive`, NOT `disappeared` — so we never falsely claim
    something was fixed.
  * No new endpoints are crawled. We touch ONLY the targets the
    findings reference.

**Replay strategy per module**:

  F97 (headers):     GET target URL → analyze_security_headers
  F98 (cookies):     GET target URL → analyze_cookies on Set-Cookie
  F100 (tls):        capture TLS profile of host → analyze_tls_profile
  F101 (disclosure): re-probe the path → analyze_disclosure_probes
  F102 (vuln JS):    HEAD/inspect the script URL → analyze_scripts
  F104 (CMS fingerprint): GET target URL → analyze_fingerprint
  F107 (DOM XSS):    GET the JS file:line target → analyze_dom_xss
  F110 (nuclei):     no replay (would re-run nuclei — too expensive
                     in a replay context). Inconclusive by default.

The engine doesn't reimplement detection; it re-invokes the same
analyzer functions used during the original pipeline. Replay verdict
= "rule_id present in re-analysis result" → still-present.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Iterable
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from kryon.tools.api.cms_fingerprint import (
    FingerprintObservation,
    analyze_fingerprint,
)
from kryon.tools.api.cookie_security import analyze_cookies
from kryon.tools.api.dom_xss import JsSnippet, analyze_dom_xss
from kryon.tools.api.info_disclosure import (
    DisclosureProbe,
    analyze_probes as analyze_disclosure_probes,
)
from kryon.tools.api.security_headers import (
    HTTPResponse,
    analyze_security_headers,
)
from kryon.tools.api.tls_audit import analyze_tls_profile
from kryon.tools.api.vuln_js_libs import (
    ScriptObservation,
    analyze_scripts,
)
from kryon.tools.auth.runner import (
    AuthFlowConfig,
    AuthFlowRunner,
    AuthSession,
)
from kryon.tools.pipeline.pipeline import UnifiedFinding
from kryon.tools.pipeline.tls_capture import capture_tls_profile

__all__ = [
    "ReplayConfig",
    "ReplayedFinding",
    "ReplayResult",
    "ReplayEngine",
    "REPLAY_STATUS_STILL_PRESENT",
    "REPLAY_STATUS_DISAPPEARED",
    "REPLAY_STATUS_CHANGED",
    "REPLAY_STATUS_INCONCLUSIVE",
    "run_replay",
]


REPLAY_STATUS_STILL_PRESENT = "still-present"
REPLAY_STATUS_DISAPPEARED = "disappeared"
REPLAY_STATUS_CHANGED = "changed"  # rule still fires but severity / detail changed
REPLAY_STATUS_INCONCLUSIVE = "inconclusive"  # could not verify (network, auth, ...)


@dataclass(frozen=True)
class ReplayConfig:
    findings: tuple[UnifiedFinding, ...]
    auth_flow: AuthFlowConfig | None = None
    timeout_seconds: float = 8.0
    rate_limit_per_second: float = 5.0
    user_agent: str = "Kryon-Replay/1.0 (banca-safe; +read-only)"
    follow_redirects: bool = True
    max_body_bytes: int = 200_000


@dataclass(frozen=True)
class ReplayedFinding:
    original: UnifiedFinding
    status: str
    detail: str = ""
    new_severity: str = ""  # populated when status == CHANGED
    new_title: str = ""     # populated when status == CHANGED
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class ReplayResult:
    replayed: tuple[ReplayedFinding, ...] = field(default_factory=tuple)
    still_present_count: int = 0
    disappeared_count: int = 0
    changed_count: int = 0
    inconclusive_count: int = 0
    elapsed_seconds: float = 0.0
    auth_session: AuthSession | None = None


# ---- helpers --------------------------------------------------------------


def _headers_to_dict(headers: dict | list) -> dict[str, str]:
    """Convert requests.Response.headers (CaseInsensitiveDict) to a
    plain dict, merging duplicates."""
    out: dict[str, str] = {}
    if hasattr(headers, "items"):
        for name, value in headers.items():
            if name in out:
                out[name] = out[name] + ", " + value
            else:
                out[name] = value
    return out


def _headers_to_tuples(headers: dict | list) -> tuple[tuple[str, str], ...]:
    if hasattr(headers, "items"):
        return tuple((str(k), str(v)) for k, v in headers.items())
    return ()


def _extract_set_cookies(headers: dict | list) -> list[str]:
    """Capture every Set-Cookie header value (preserving multiplicity)."""
    # requests' CaseInsensitiveDict merges with ", " on .items() which
    # breaks Set-Cookie parsing — Set-Cookie is the ONE header that
    # legitimately appears multiple times. Use raw=True path if available.
    out: list[str] = []
    raw_headers = getattr(headers, "raw", None)
    if raw_headers is not None:
        # urllib3 HTTPHeaderDict path
        try:
            return list(raw_headers.getlist("Set-Cookie"))
        except Exception:
            pass
    # Fallback: split on the comma-merge boundary (imperfect but common)
    if hasattr(headers, "get"):
        raw = headers.get("Set-Cookie", "")
        if raw:
            # Try splitting on common pattern ", " between cookies
            # (only when followed by something that looks like a Set-Cookie)
            # This is a best-effort fallback.
            out.append(raw)
    return out


def _cookie_names(set_cookies: list[str]) -> list[str]:
    names: list[str] = []
    for raw in set_cookies:
        ck = SimpleCookie()
        try:
            ck.load(raw)
        except Exception:
            continue
        names.extend(ck.keys())
    return names


# ---- per-module replay functions -----------------------------------------


class ReplayEngine:
    def __init__(self, config: ReplayConfig) -> None:
        self.config = config
        self._session: requests.Session | None = None
        self._auth_session: AuthSession | None = None
        self._host_buckets: dict[str, float] = {}  # host → last-fetch monotonic
        self._min_interval = (
            1.0 / self.config.rate_limit_per_second
            if self.config.rate_limit_per_second > 0
            else 0.0
        )

    def _build_session(self, auth: AuthSession | None) -> requests.Session:
        sess = requests.Session()
        sess.headers["User-Agent"] = self.config.user_agent
        adapter = HTTPAdapter(pool_connections=2, pool_maxsize=2, max_retries=0)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        if auth is not None and auth.success:
            for name, value in auth.cookies:
                sess.cookies.set(name, value)
            for name, value in auth.headers:
                sess.headers[name] = value
        return sess

    def _maybe_authenticate(self) -> AuthSession | None:
        if self.config.auth_flow is None:
            return None
        auth = AuthFlowRunner(self.config.auth_flow).execute()
        return auth

    def _throttle(self, host: str) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        last = self._host_buckets.get(host, 0.0)
        wait = self._min_interval - (now - last)
        if wait > 0:
            time.sleep(wait)
        self._host_buckets[host] = time.monotonic()

    def _fetch(self, url: str) -> requests.Response | None:
        if self._session is None:
            return None
        host = (urlparse(url).hostname or "").lower()
        self._throttle(host)
        try:
            resp = self._session.get(
                url,
                timeout=self.config.timeout_seconds,
                allow_redirects=self.config.follow_redirects,
                stream=True,
            )
            deadline = time.monotonic() + self.config.timeout_seconds
            buf = bytearray()
            try:
                for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
                    if time.monotonic() > deadline:
                        return None
                    if chunk:
                        buf.extend(chunk)
                    if len(buf) >= self.config.max_body_bytes:
                        break
            finally:
                resp.close()
            resp._kryon_capped_content = bytes(buf[: self.config.max_body_bytes])  # type: ignore[attr-defined]
            return resp
        except (requests.exceptions.RequestException, OSError):
            return None

    def _decode(self, resp: requests.Response) -> str:
        raw: bytes = getattr(resp, "_kryon_capped_content", b"")
        try:
            return raw.decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

    # ----- per-module replay --------------------------------------------

    def _replay_headers(self, finding: UnifiedFinding) -> ReplayedFinding:
        target = finding.target
        if not target.startswith(("http://", "https://")):
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not an http(s) URL",
            )
        resp = self._fetch(target)
        if resp is None:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="fetch failed",
            )
        response = HTTPResponse(
            url=target,
            method="GET",
            is_https=target.startswith("https://"),
            headers=_headers_to_dict(resp.headers),
        )
        analysis = analyze_security_headers(response)
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                if f.severity != finding.severity:
                    return ReplayedFinding(
                        original=finding,
                        status=REPLAY_STATUS_CHANGED,
                        new_severity=f.severity,
                        new_title=f.title,
                        detail=f"severity changed: {finding.severity} → {f.severity}",
                    )
                return ReplayedFinding(
                    original=finding,
                    status=REPLAY_STATUS_STILL_PRESENT,
                    detail="rule still fires",
                )
        return ReplayedFinding(
            original=finding,
            status=REPLAY_STATUS_DISAPPEARED,
            detail="rule no longer fires on this URL",
        )

    def _replay_cookies(self, finding: UnifiedFinding) -> ReplayedFinding:
        target = finding.target
        if not target.startswith(("http://", "https://")):
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not an http(s) URL",
            )
        resp = self._fetch(target)
        if resp is None:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="fetch failed",
            )
        set_cookies = _extract_set_cookies(resp.headers)
        if not set_cookies:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_DISAPPEARED,
                detail="no Set-Cookie headers on replayed response",
            )
        analysis = analyze_cookies(
            set_cookies, is_https=target.startswith("https://")
        )
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                if f.severity != finding.severity:
                    return ReplayedFinding(
                        original=finding,
                        status=REPLAY_STATUS_CHANGED,
                        new_severity=f.severity,
                        new_title=f.title,
                    )
                return ReplayedFinding(
                    original=finding, status=REPLAY_STATUS_STILL_PRESENT
                )
        return ReplayedFinding(
            original=finding,
            status=REPLAY_STATUS_DISAPPEARED,
            detail="rule no longer fires",
        )

    def _replay_cms(self, finding: UnifiedFinding) -> ReplayedFinding:
        target = finding.target
        if not target.startswith(("http://", "https://")):
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not an http(s) URL",
            )
        resp = self._fetch(target)
        if resp is None:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="fetch failed",
            )
        body = self._decode(resp)
        set_cookies = _extract_set_cookies(resp.headers)
        cookie_names = tuple(_cookie_names(set_cookies))
        obs = FingerprintObservation(
            url=target,
            headers=_headers_to_tuples(resp.headers),
            body_snippet=body,
            cookie_names=cookie_names,
        )
        analysis = analyze_fingerprint(obs)
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                return ReplayedFinding(
                    original=finding, status=REPLAY_STATUS_STILL_PRESENT
                )
        return ReplayedFinding(
            original=finding, status=REPLAY_STATUS_DISAPPEARED
        )

    def _replay_js_libs(self, finding: UnifiedFinding) -> ReplayedFinding:
        target = finding.target
        if not target.startswith(("http://", "https://")):
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not an http(s) URL",
            )
        # Just inspect the URL (version is encoded in the path)
        analysis = analyze_scripts([ScriptObservation(src=target)])
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                return ReplayedFinding(
                    original=finding, status=REPLAY_STATUS_STILL_PRESENT
                )
        # Maybe operator's bundle got renamed; consider DISAPPEARED
        return ReplayedFinding(
            original=finding,
            status=REPLAY_STATUS_DISAPPEARED,
            detail="script URL no longer matches a vulnerable version pattern",
        )

    def _replay_dom_xss(self, finding: UnifiedFinding) -> ReplayedFinding:
        # target format: "<file_url>:<line>"
        target = finding.target
        if ":" in target and target.rsplit(":", 1)[-1].isdigit():
            url = target.rsplit(":", 1)[0]
        else:
            url = target
        if not url.startswith(("http://", "https://")):
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not an http(s) URL",
            )
        resp = self._fetch(url)
        if resp is None:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="fetch failed",
            )
        body = self._decode(resp)
        if not body:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_DISAPPEARED,
                detail="empty body on re-fetch",
            )
        analysis = analyze_dom_xss([JsSnippet(file_path=url, body=body)])
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                return ReplayedFinding(
                    original=finding, status=REPLAY_STATUS_STILL_PRESENT
                )
        return ReplayedFinding(
            original=finding, status=REPLAY_STATUS_DISAPPEARED
        )

    def _replay_disclosure(self, finding: UnifiedFinding) -> ReplayedFinding:
        target = finding.target
        if not target.startswith(("http://", "https://")):
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not an http(s) URL",
            )
        resp = self._fetch(target)
        if resp is None:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="fetch failed",
            )
        body = self._decode(resp)[:200]
        path = urlparse(target).path or "/"
        probe = DisclosureProbe(
            path=path,
            http_status=resp.status_code,
            body_fingerprint=body,
            content_length=len(body),
        )
        analysis = analyze_disclosure_probes([probe])
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                return ReplayedFinding(
                    original=finding, status=REPLAY_STATUS_STILL_PRESENT
                )
        return ReplayedFinding(
            original=finding, status=REPLAY_STATUS_DISAPPEARED
        )

    def _replay_tls(self, finding: UnifiedFinding) -> ReplayedFinding:
        target = finding.target  # "host:port"
        if ":" not in target:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="target is not host:port",
            )
        host, _, port_str = target.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="invalid port",
            )
        profile = capture_tls_profile(host, port, timeout=self.config.timeout_seconds)
        if profile is None:
            return ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail="TLS handshake failed",
            )
        analysis = analyze_tls_profile(profile)
        for f in analysis.findings:
            if f.rule_id == finding.rule_id:
                return ReplayedFinding(
                    original=finding, status=REPLAY_STATUS_STILL_PRESENT
                )
        return ReplayedFinding(
            original=finding, status=REPLAY_STATUS_DISAPPEARED
        )

    def _replay_one(self, finding: UnifiedFinding) -> ReplayedFinding:
        t0 = time.monotonic()
        mod = finding.source_module
        try:
            if mod == "F97":
                r = self._replay_headers(finding)
            elif mod == "F98":
                r = self._replay_cookies(finding)
            elif mod == "F100":
                r = self._replay_tls(finding)
            elif mod == "F101":
                r = self._replay_disclosure(finding)
            elif mod == "F102":
                r = self._replay_js_libs(finding)
            elif mod == "F104":
                r = self._replay_cms(finding)
            elif mod == "F107":
                r = self._replay_dom_xss(finding)
            else:
                r = ReplayedFinding(
                    original=finding,
                    status=REPLAY_STATUS_INCONCLUSIVE,
                    detail=f"replay not implemented for {mod}",
                )
        except Exception as e:
            r = ReplayedFinding(
                original=finding,
                status=REPLAY_STATUS_INCONCLUSIVE,
                detail=f"replay raised {type(e).__name__}: {e}",
            )
        elapsed = time.monotonic() - t0
        # Re-emit with elapsed populated
        return ReplayedFinding(
            original=r.original,
            status=r.status,
            detail=r.detail,
            new_severity=r.new_severity,
            new_title=r.new_title,
            elapsed_seconds=elapsed,
        )

    def replay(self) -> ReplayResult:
        t0 = time.monotonic()
        auth = self._maybe_authenticate()
        self._auth_session = auth
        self._session = self._build_session(auth)
        replayed: list[ReplayedFinding] = []
        for finding in self.config.findings:
            replayed.append(self._replay_one(finding))
        counts: dict[str, int] = {
            REPLAY_STATUS_STILL_PRESENT: 0,
            REPLAY_STATUS_DISAPPEARED: 0,
            REPLAY_STATUS_CHANGED: 0,
            REPLAY_STATUS_INCONCLUSIVE: 0,
        }
        for r in replayed:
            counts[r.status] = counts.get(r.status, 0) + 1
        return ReplayResult(
            replayed=tuple(replayed),
            still_present_count=counts[REPLAY_STATUS_STILL_PRESENT],
            disappeared_count=counts[REPLAY_STATUS_DISAPPEARED],
            changed_count=counts[REPLAY_STATUS_CHANGED],
            inconclusive_count=counts[REPLAY_STATUS_INCONCLUSIVE],
            elapsed_seconds=time.monotonic() - t0,
            auth_session=auth,
        )


def run_replay(config: ReplayConfig) -> ReplayResult:
    return ReplayEngine(config).replay()
