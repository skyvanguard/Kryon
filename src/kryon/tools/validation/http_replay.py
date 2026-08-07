"""Fase 2 — deterministic headless HTTP-replay validators (XSS / SSRF / IDOR).

The existing ``exploit_validator`` confirms findings by shelling out to heavy
external tools (sqlmap, dalfox, commix, hydra) — slow, noisy, and with no
coverage at all for SSRF or IDOR. This module is the deterministic sibling:
it re-issues ONE crafted HTTP request with a unique canary and adjudicates the
finding from the response alone — no external binary, no LLM, no OAST server.

Design (mirrors verification_bridge / dynamic_oracle)
-----------------------------------------------------
The single impure dependency — the HTTP round-trip — is an injected callable,
so the whole adjudication is pure and unit-testable with a fake fetcher (no
network). ``default_fetch`` is the real stdlib-urllib implementation.

Each validator returns a typed :class:`ReplayResult` with a hard verdict:

- ``confirmed``      — the canary proves exploitation (reflected-unescaped tag,
  echoed SSRF token, cross-tenant object read). Ground truth, not a hunch.
- ``not-reproduced`` — the request went through but the canary signal is absent
  (escaped output, 401/403 on the sibling object, no token echo).
- ``inconclusive``   — the request could not run (network error / timeout).
- ``dry_run``        — gates not satisfied; no traffic was sent.
- ``unsupported``    — the finding type isn't one this module replays.

Banca-safety
------------
Double gate: ``KRYON_REPLAY_FIRE=true`` env AND ``fire=True`` kwarg. Default is
DRY-RUN (no packets). GET-only — these three classes are all provable with a
single GET, so no mutating verb is ever issued. Response body is capped and only
a short evidence excerpt is kept; full bodies are never persisted.
"""

from __future__ import annotations

import html
import os
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

__all__ = [
    "HttpResponse",
    "ReplayResult",
    "HttpFetch",
    "default_fetch",
    "replay_reflected_xss",
    "replay_reflected_ssrf",
    "replay_idor",
    "validate_web_finding",
    "replay_type_for_cwe",
    "is_replay_verifiable",
    "REPLAY_VERIFIABLE_TYPES",
]

_RESPONSE_CAP_BYTES = 2 * 1024 * 1024  # 2 MB, same as the retester
_EVIDENCE_CHARS = 240
_DEFAULT_TIMEOUT = 20

# Finding types this module can adjudicate deterministically.
REPLAY_VERIFIABLE_TYPES: frozenset[str] = frozenset({"xss", "ssrf", "idor"})

# CWE -> replay type. The applicability gate for the auto-wire: a caller with an
# engage.Finding asks ``replay_type_for_cwe(finding.cwe)`` and routes only the
# classes this module can prove headlessly (mirrors is_asan_verifiable /
# is_dynamic_verifiable in the sibling oracles).
_CWE_TO_TYPE: dict[str, str] = {
    "CWE-79": "xss",  # reflected/stored XSS
    "CWE-80": "xss",  # basic XSS
    "CWE-918": "ssrf",  # server-side request forgery
    "CWE-639": "idor",  # authorization bypass via user-controlled key
    "CWE-566": "idor",  # authz bypass via SQL primary key
    "CWE-284": "idor",  # improper access control (object-level)
}


@dataclass(frozen=True)
class HttpResponse:
    """A minimal HTTP response the validators reason over."""

    status: int
    body: str
    headers: dict[str, str]
    error: str = ""  # transport-level failure; status/body meaningless when set


@dataclass(frozen=True)
class ReplayResult:
    """One validator's hard verdict for a finding."""

    verdict: str  # confirmed | not-reproduced | inconclusive | dry_run | unsupported
    cwe: str
    method: str  # which replay technique produced the verdict
    evidence: str  # short excerpt proving (or refuting) the verdict
    payload: str = ""  # the canary/probe that was sent, for the audit trail


# (method, url, headers, timeout) -> HttpResponse. Injected so tests need no net.
HttpFetch = Callable[[str, str, "dict[str, str]", int], HttpResponse]


def _fire_enabled(fire: bool) -> bool:
    """Double gate: the kwarg AND the env must both opt in."""
    if not fire:
        return False
    return os.environ.get("KRYON_REPLAY_FIRE", "").strip().lower() in ("1", "true", "yes")


def _dry_run(cwe: str, method: str, payload: str) -> ReplayResult:
    return ReplayResult(
        verdict="dry_run",
        cwe=cwe,
        method=method,
        evidence=("dry-run: no HTTP sent. Set KRYON_REPLAY_FIRE=true and pass fire=True to execute."),
        payload=payload,
    )


def default_fetch(method: str, url: str, headers: dict[str, str], timeout: int) -> HttpResponse:
    """Real GET-only HTTP round-trip via stdlib urllib. Caps the body, never
    follows a mutating verb (this module only ever asks for GET)."""
    if method.upper() != "GET":  # defensive — validators never pass anything else
        return HttpResponse(status=0, body="", headers={}, error=f"refusing non-GET verb {method}")
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — GET-only, gated
            raw = resp.read(_RESPONSE_CAP_BYTES)
            resp_headers = dict(resp.headers.items())
            status = resp.status
    except HTTPError as e:
        try:
            raw = e.read(_RESPONSE_CAP_BYTES)
        except Exception:  # noqa: BLE001
            raw = b""
        resp_headers = dict((e.headers or {}).items())
        status = e.code
    except (URLError, TimeoutError, OSError) as e:
        return HttpResponse(status=0, body="", headers={}, error=f"{type(e).__name__}: {e}")
    return HttpResponse(
        status=status,
        body=raw.decode("utf-8", errors="replace"),
        headers=resp_headers,
    )


def _inject_param(url: str, parameter: str, value: str) -> str:
    """Return ``url`` with ``parameter`` set to ``value`` in the query string.

    Replaces the parameter if already present, appends it otherwise. Preserves
    the rest of the query verbatim so we probe the same endpoint the finding hit.
    """
    parts = urlparse(url)
    pairs: list[tuple[str, str]] = []
    replaced = False
    if parts.query:
        for chunk in parts.query.split("&"):
            if not chunk:
                continue
            key, _, existing = chunk.partition("=")
            if key == parameter:
                pairs.append((key, value))
                replaced = True
            else:
                pairs.append((key, existing))
    if not replaced:
        pairs.append((parameter, value))
    new_query = urlencode(pairs)
    return urlunparse(parts._replace(query=new_query))


# ---------------------------------------------------------------------------
# CWE-79 — reflected XSS
# ---------------------------------------------------------------------------


def replay_reflected_xss(
    url: str,
    parameter: str,
    *,
    fetch: HttpFetch | None = None,
    fire: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> ReplayResult:
    """Confirm reflected XSS by injecting a unique breakout tag and checking
    whether it comes back UNESCAPED.

    The canary is a bespoke element (``<kryonxss id=...>``) that never appears in
    normal output, so a literal, un-encoded reflection is unambiguous proof the
    parameter reaches the HTML sink without escaping. If the same marker comes
    back HTML-entity-encoded (``&lt;kryonxss``), the sink escapes → not reproduced.
    """
    cwe = "CWE-79"
    token = _new_canary("xss")
    # Breakout out of a possible attribute/tag context, then a marker element.
    payload = f'"><kryonxss id={token}>'
    if not _fire_enabled(fire):
        return _dry_run(cwe, "reflected-canary", payload)

    fetch = fetch or default_fetch
    probe_url = _inject_param(url, parameter, payload)
    resp = fetch("GET", probe_url, headers or {}, timeout)
    if resp.error:
        return ReplayResult("inconclusive", cwe, "reflected-canary", resp.error[:_EVIDENCE_CHARS], payload)

    unescaped_marker = f"<kryonxss id={token}>"
    escaped_marker = html.escape(unescaped_marker, quote=False)  # &lt;kryonxss id=...&gt;
    body = resp.body
    if unescaped_marker in body:
        excerpt = _excerpt_around(body, unescaped_marker)
        return ReplayResult("confirmed", cwe, "reflected-canary", excerpt, payload)
    if escaped_marker in body:
        return ReplayResult(
            "not-reproduced",
            cwe,
            "reflected-canary",
            f"marker reflected but HTML-escaped: {escaped_marker}",
            payload,
        )
    return ReplayResult(
        "not-reproduced",
        cwe,
        "reflected-canary",
        "canary not reflected in response body",
        payload,
    )


# ---------------------------------------------------------------------------
# CWE-918 — (in-band / reflected) SSRF
# ---------------------------------------------------------------------------


def replay_reflected_ssrf(
    url: str,
    parameter: str,
    marker_url: str,
    expected_token: str,
    *,
    fetch: HttpFetch | None = None,
    fire: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> ReplayResult:
    """Confirm in-band SSRF by asking the server to fetch a URL we control and
    checking whether its distinctive content is echoed back.

    ``marker_url`` is a resource whose response the operator knows (their own
    canary endpoint, or an internal service like the cloud metadata IP), and
    ``expected_token`` is a string that only appears when that URL was actually
    fetched. Echoed token → the server made the request → SSRF confirmed. This is
    the deterministic in-band case; blind SSRF needs an OAST listener (out of
    scope for a headless replay).
    """
    cwe = "CWE-918"
    if not _fire_enabled(fire):
        return _dry_run(cwe, "in-band-echo", marker_url)
    if not expected_token.strip():
        return ReplayResult(
            "inconclusive",
            cwe,
            "in-band-echo",
            "no expected_token supplied — cannot adjudicate in-band SSRF deterministically",
            marker_url,
        )

    fetch = fetch or default_fetch
    probe_url = _inject_param(url, parameter, marker_url)
    resp = fetch("GET", probe_url, headers or {}, timeout)
    if resp.error:
        return ReplayResult("inconclusive", cwe, "in-band-echo", resp.error[:_EVIDENCE_CHARS], marker_url)

    if expected_token in resp.body:
        return ReplayResult(
            "confirmed",
            cwe,
            "in-band-echo",
            _excerpt_around(resp.body, expected_token),
            marker_url,
        )
    return ReplayResult(
        "not-reproduced",
        cwe,
        "in-band-echo",
        "marker URL content not echoed — server did not fetch it (or blind SSRF)",
        marker_url,
    )


# ---------------------------------------------------------------------------
# CWE-639 — IDOR / broken object-level authorization
# ---------------------------------------------------------------------------


def replay_idor(
    url: str,
    id_parameter: str,
    own_id: str,
    other_id: str,
    *,
    fetch: HttpFetch | None = None,
    fire: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
    session_headers: dict[str, str] | None = None,
) -> ReplayResult:
    """Confirm IDOR by requesting a sibling object with the SAME session.

    Fetches ``own_id`` (the attacker's legitimate object) and ``other_id`` (a
    neighbour's) with identical ``session_headers``. If the neighbour returns a
    ``200`` with a non-empty body that DIFFERS from the attacker's own object,
    the server served someone else's data to this session → IDOR confirmed. A
    ``401/403/404`` or an identical/empty body on the sibling → authorization is
    enforced (not reproduced).
    """
    cwe = "CWE-639"
    if not _fire_enabled(fire):
        return _dry_run(cwe, "sibling-object", f"{id_parameter}={own_id}->{other_id}")

    fetch = fetch or default_fetch
    hdrs = session_headers or {}
    own_url = _inject_param(url, id_parameter, own_id)
    other_url = _inject_param(url, id_parameter, other_id)
    own = fetch("GET", own_url, hdrs, timeout)
    other = fetch("GET", other_url, hdrs, timeout)
    if own.error or other.error:
        return ReplayResult(
            "inconclusive",
            cwe,
            "sibling-object",
            (own.error or other.error)[:_EVIDENCE_CHARS],
            f"{own_id}->{other_id}",
        )

    if other.status in (401, 403, 404):
        return ReplayResult(
            "not-reproduced",
            cwe,
            "sibling-object",
            f"sibling object returned {other.status} — access control enforced",
            f"{own_id}->{other_id}",
        )
    other_body = other.body.strip()
    if other.status == 200 and other_body and other_body != own.body.strip():
        return ReplayResult(
            "confirmed",
            cwe,
            "sibling-object",
            f"sibling id={other_id} returned 200 with distinct data: {other_body[:_EVIDENCE_CHARS]}",
            f"{own_id}->{other_id}",
        )
    return ReplayResult(
        "not-reproduced",
        cwe,
        "sibling-object",
        f"sibling returned status={other.status}, body identical/empty — no cross-tenant read",
        f"{own_id}->{other_id}",
    )


# ---------------------------------------------------------------------------
# dispatcher
# ---------------------------------------------------------------------------


def validate_web_finding(
    finding_type: str,
    url: str,
    *,
    parameter: str = "",
    marker_url: str = "",
    expected_token: str = "",
    own_id: str = "",
    other_id: str = "",
    fetch: HttpFetch | None = None,
    fire: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> ReplayResult:
    """Route a web finding to its deterministic replay validator.

    Returns ``unsupported`` for anything outside {xss, ssrf, idor} — the caller
    should fall back to ``exploit_validator`` (sqlmap/dalfox/commix/hydra) or the
    SAST oracles for those classes.
    """
    kind = _normalize_type(finding_type)
    if kind == "xss":
        return replay_reflected_xss(url, parameter, fetch=fetch, fire=fire, timeout=timeout, headers=headers)
    if kind == "ssrf":
        return replay_reflected_ssrf(
            url,
            parameter,
            marker_url,
            expected_token,
            fetch=fetch,
            fire=fire,
            timeout=timeout,
            headers=headers,
        )
    if kind == "idor":
        return replay_idor(
            url,
            parameter,
            own_id,
            other_id,
            fetch=fetch,
            fire=fire,
            timeout=timeout,
            session_headers=headers,
        )
    return ReplayResult(
        "unsupported",
        "",
        "none",
        f"'{finding_type}' is not a replay-verifiable class (xss/ssrf/idor)",
        "",
    )


_TYPE_ALIASES = {
    "xss": "xss",
    "reflected_xss": "xss",
    "reflected-xss": "xss",
    "cross-site scripting": "xss",
    "cross_site_scripting": "xss",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "server_side_request_forgery": "ssrf",
    "idor": "idor",
    "insecure_direct_object_reference": "idor",
    "broken_object_level_authorization": "idor",
    "bola": "idor",
}


def _normalize_type(finding_type: str) -> str:
    return _TYPE_ALIASES.get(finding_type.strip().lower(), finding_type.strip().lower())


def replay_type_for_cwe(cwe: str) -> str | None:
    """Return the replay type ('xss'|'ssrf'|'idor') for a CWE, or None.

    The applicability gate for the auto-wire: a finding-verification pass calls
    this to decide whether a web finding can be adjudicated headlessly before
    routing it to :func:`validate_web_finding`.
    """
    return _CWE_TO_TYPE.get(cwe.upper().strip())


def is_replay_verifiable(cwe: str) -> bool:
    """True if ``cwe`` maps to one of the headless replay classes (79/918/639…)."""
    return replay_type_for_cwe(cwe) is not None


def _new_canary(prefix: str) -> str:
    """A per-call unique marker. Uses os.urandom (Math.random is banned in some
    contexts and this must be collision-free across concurrent probes)."""
    return prefix + os.urandom(6).hex()


def _excerpt_around(body: str, needle: str, *, window: int = _EVIDENCE_CHARS) -> str:
    idx = body.find(needle)
    if idx == -1:
        return body[:window]
    start = max(0, idx - window // 4)
    return body[start : start + window]
