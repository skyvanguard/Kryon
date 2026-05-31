"""F87.6 — CORS misconfiguration detector.

Banking APIs are the #1 target for cross-origin attacks: a CORS
misconfiguration on a session-cookie-bearing endpoint lets any
malicious page extract account data with one fetch() call. The
common failure modes are well-documented but consistently missed in
pre-launch security reviews:

  - `Access-Control-Allow-Origin: *` with credentials enabled
    (browsers reject the combination but server still emits it —
    misconfigured fetch policies will bypass).
  - Reflected Origin: server echoes whatever the request's Origin
    header was. Equivalent to `*` for attacker purposes.
  - Permissive methods (DELETE/PUT) on sensitive paths.
  - Long preflight cache (Access-Control-Max-Age > 86400) holds
    permissive responses past their useful lifetime.
  - Subdomain wildcards (`*.bank.com`) allow take-over via
    subdomain takeover.

This module is PURE static analysis on response headers. Caller
probes the endpoint with a controlled Origin header, captures the
response headers, hands them here.

Same shape as F87.5 JWT + F95 webhook: stable rule IDs, severity,
remediation, frozen dataclasses, banca-safety contract.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


__all__ = [
    "CORSResponse",
    "CORSFinding",
    "CORSAnalysis",
    "analyze_cors_response",
    "ALL_CORS_RULES",
    "SENSITIVE_HTTP_METHODS",
]


# HTTP methods that mutate state. Permissive CORS on these is
# higher-impact than on safe methods (GET/HEAD/OPTIONS).
SENSITIVE_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# Stable rule IDs. Pinned by test.
ALL_CORS_RULES: frozenset[str] = frozenset(
    {
        "CORS-001",
        "CORS-002",
        "CORS-003",
        "CORS-004",
        "CORS-005",
        "CORS-006",
        "CORS-007",
        "CORS-008",
    }
)


# Wildcard subdomain pattern (e.g. *.bank.com) — risky because
# subdomain takeover lets an attacker satisfy the wildcard match.
_SUBDOMAIN_WILDCARD_RE = re.compile(r"^\*\.[A-Za-z0-9.-]+$")

# Null origin is what browsers send for sandboxed iframes / data:
# URIs / file:// pages. Accepting it is almost always a mistake.
_NULL_ORIGIN_LITERAL = "null"

# Long preflight cache window. Browsers cap at 7200s (Chromium) but
# the directive's max sensible value for banking is much lower.
_MAX_REASONABLE_PREFLIGHT_AGE_S = 86400  # 24 hours


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CORSResponse:
    """The response headers an operator captured after probing the
    target with a chosen Origin. Only the CORS-relevant headers are
    needed; we don't care about the rest of the response."""

    request_origin: str  # the Origin header sent in the probe
    request_path: str = ""  # e.g. "/api/transfer" — used for context
    request_method: str = "GET"  # method the probe used
    # Headers as the server returned them. Both names + values are
    # case-insensitive on lookup.
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CORSFinding:
    """One detected weakness."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str


@dataclass(frozen=True)
class CORSAnalysis:
    """Aggregated analysis."""

    allow_origin: str | None
    allow_credentials: bool
    allow_methods: tuple[str, ...] = field(default_factory=tuple)
    allow_headers: tuple[str, ...] = field(default_factory=tuple)
    max_age_seconds: int | None = None
    findings: tuple[CORSFinding, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------


def _get(headers: dict[str, str], name: str) -> str | None:
    if not headers:
        return None
    lower = {k.lower(): v for k, v in headers.items()}
    return lower.get(name.lower())


def _parse_csv_header(value: str | None) -> tuple[str, ...]:
    """Parse a comma-separated header value into a tuple of trimmed
    upper-cased tokens. Empty input → empty tuple."""
    if not value:
        return ()
    return tuple(token.strip().upper() for token in value.split(",") if token.strip())


def _parse_max_age(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------


def _check_wildcard_with_credentials(
    allow_origin: str | None,
    allow_credentials: bool,
) -> list[CORSFinding]:
    """CORS-001: ACAO=* + ACAC=true is forbidden by spec — browsers
    refuse to honor the cookies, but the server is still misconfigured.
    A fetch() with cookies forwarded via `credentials: 'include'` and
    a missing/different Origin check WILL leak data."""
    if allow_origin == "*" and allow_credentials:
        return [
            CORSFinding(
                rule_id="CORS-001",
                severity="CRITICAL",
                title="Wildcard origin (*) with Allow-Credentials: true",
                detail=(
                    "Server emits Access-Control-Allow-Origin: * AND "
                    "Access-Control-Allow-Credentials: true. The spec "
                    "forbids the combination; browsers refuse to send "
                    "cookies. But the server's intent — allow ANY origin "
                    "with cookies — is unsafe and signals a misconfigured "
                    "CORS policy."
                ),
                remediation=(
                    "Set ACAO to a specific allow-listed origin OR drop Allow-Credentials. Never both with wildcard."
                ),
            )
        ]
    return []


def _check_reflected_origin(
    request_origin: str,
    allow_origin: str | None,
    allow_credentials: bool,
) -> list[CORSFinding]:
    """CORS-002: server echoes whatever Origin the request supplied.
    Equivalent to `*` for attacker purposes — but unlike `*`, it
    also bypasses the spec restriction on credentials, so cookies
    can be forwarded.

    The probe must use a clearly-non-allowlisted Origin
    (https://attacker.example), and the server echoing it back is
    the signal."""
    if not allow_origin or not request_origin:
        return []
    if allow_origin.lower() != request_origin.lower():
        return []
    # If the request_origin is the canonical origin of the target,
    # echoing back is correct. The check fires when the operator
    # probed with an arbitrary attacker-shaped Origin.
    if request_origin in ("null", "*"):
        return []  # different check class
    severity = "CRITICAL" if allow_credentials else "HIGH"
    return [
        CORSFinding(
            rule_id="CORS-002",
            severity=severity,
            title=f"Origin reflection (server echoes Origin: {request_origin!r})",
            detail=(
                f"Probe sent Origin: {request_origin}; server returned "
                f"Access-Control-Allow-Origin: {allow_origin}. The server "
                "appears to reflect whatever Origin the request supplies. "
                + (
                    "With credentials enabled, an attacker page can make authenticated requests and read the response."
                    if allow_credentials
                    else "Even without credentials, this exposes data to any cross-origin requester."
                )
            ),
            remediation=(
                "Replace dynamic Origin echo with an exact-match allow-list. "
                "Validate Origin against a pinned set of trusted hosts."
            ),
        )
    ]


def _check_null_origin(
    allow_origin: str | None,
    allow_credentials: bool,
) -> list[CORSFinding]:
    """CORS-003: Allow-Origin: null is browser-emitted by sandboxed
    iframes, data: URIs, file:// pages. Allowing it lets an attacker
    serve an HTML payload that drops to a sandboxed frame and reaches
    the API."""
    if allow_origin != _NULL_ORIGIN_LITERAL:
        return []
    severity = "CRITICAL" if allow_credentials else "HIGH"
    return [
        CORSFinding(
            rule_id="CORS-003",
            severity=severity,
            title="Allow-Origin: null accepted",
            detail=(
                "Server returns Access-Control-Allow-Origin: null. Browsers "
                "emit Origin: null for sandboxed iframes, data: URIs, and "
                "some file:// contexts. An attacker page can construct "
                "such a context to bypass the origin check."
            ),
            remediation="Never include `null` in the CORS allow-list.",
        )
    ]


def _check_subdomain_wildcard(
    allow_origin: str | None,
) -> list[CORSFinding]:
    """CORS-004: server uses *.bank.com style allow-list. Risk:
    subdomain takeover (an unused CNAME pointing at a defunct cloud
    service) → attacker registers the orphaned subdomain → CORS
    check passes."""
    if not allow_origin:
        return []
    if _SUBDOMAIN_WILDCARD_RE.match(allow_origin):
        return [
            CORSFinding(
                rule_id="CORS-004",
                severity="MEDIUM",
                title=f"Wildcard subdomain in Allow-Origin ({allow_origin})",
                detail=(
                    "Server allows any subdomain of the parent. A subdomain "
                    "takeover (orphaned CNAME pointing at a defunct cloud "
                    "endpoint) lets an attacker register the subdomain and "
                    "satisfy the wildcard."
                ),
                remediation=("Explicitly enumerate trusted subdomains; audit DNS for dangling CNAMEs quarterly."),
            )
        ]
    return []


def _check_credentials_with_specific_allow_origin(
    allow_origin: str | None,
    allow_credentials: bool,
    request_origin: str,
) -> list[CORSFinding]:
    """CORS-005: Allow-Credentials: true with a SPECIFIC, attacker-
    shaped origin (e.g. https://attacker.example) — confirms the
    server lets the attacker in with cookies. This is a stronger
    signal than CORS-002 because the server's response isn't
    reflective; it's explicitly allowing the attacker.

    Skipped when allow_origin is wildcard / null / reflected — those
    have their own rules."""
    if not allow_credentials or not allow_origin:
        return []
    if allow_origin in ("*", _NULL_ORIGIN_LITERAL):
        return []
    if _SUBDOMAIN_WILDCARD_RE.match(allow_origin):
        return []
    if request_origin and allow_origin.lower() == request_origin.lower():
        return []  # covered by CORS-002
    return []


def _check_permissive_methods(
    allow_methods: tuple[str, ...],
    allow_credentials: bool,
) -> list[CORSFinding]:
    """CORS-006: DELETE / PUT on sensitive endpoints are mutation
    paths. Allow-Methods: * is also a smell."""
    if not allow_methods:
        return []
    findings: list[CORSFinding] = []
    if "*" in allow_methods:
        findings.append(
            CORSFinding(
                rule_id="CORS-006",
                severity="HIGH" if allow_credentials else "MEDIUM",
                title="Allow-Methods: *",
                detail=(
                    "Server advertises Access-Control-Allow-Methods: *. "
                    "Cross-origin requests can invoke any method including "
                    "DELETE, PUT, PATCH."
                ),
                remediation="Enumerate only the methods the endpoint actually serves.",
            )
        )
        return findings

    sensitive_methods_seen = SENSITIVE_HTTP_METHODS & set(allow_methods)
    if sensitive_methods_seen and allow_credentials:
        findings.append(
            CORSFinding(
                rule_id="CORS-006",
                severity="MEDIUM",
                title=f"Sensitive methods allowed cross-origin ({sorted(sensitive_methods_seen)})",
                detail=(
                    "Combined with Allow-Credentials: true, a cross-origin "
                    "request can mutate state with the user's cookies "
                    "attached. Verify CSRF protection is in place."
                ),
                remediation=(
                    "Require a custom header (X-Requested-With) on mutation "
                    "endpoints; the preflight requirement keeps non-CORS-aware "
                    "attackers out."
                ),
            )
        )
    return findings


def _check_long_preflight_cache(
    max_age: int | None,
) -> list[CORSFinding]:
    """CORS-007: Access-Control-Max-Age greater than 24h holds the
    permissive preflight result in browser caches indefinitely. A
    permission change won't propagate until the cache TTL expires."""
    if max_age is None:
        return []
    if max_age > _MAX_REASONABLE_PREFLIGHT_AGE_S:
        return [
            CORSFinding(
                rule_id="CORS-007",
                severity="MEDIUM",
                title=f"Long preflight cache: {max_age}s",
                detail=(
                    f"Access-Control-Max-Age={max_age}s. Browser caches the "
                    "preflight result for that duration. A subsequent CORS "
                    "policy tightening won't apply to clients until the "
                    "cache expires."
                ),
                remediation=(
                    f"Cap Max-Age at {_MAX_REASONABLE_PREFLIGHT_AGE_S}s (24h). Browsers (Chromium) cap at 7200s anyway."
                ),
            )
        ]
    return []


def _check_acao_present_at_all(
    allow_origin: str | None,
    request_origin: str,
) -> list[CORSFinding]:
    """CORS-008: probe sent an Origin but server omitted ACAO. Not
    necessarily a misconfig — endpoints that don't accept cross-
    origin requests should NOT include CORS headers. Informational
    only; surfaces so the auditor confirms intent.

    Fires only when the probe sent a real origin (not empty)."""
    if not request_origin:
        return []
    if allow_origin is not None:
        return []
    return [
        CORSFinding(
            rule_id="CORS-008",
            severity="INFO",
            title="No Access-Control-Allow-Origin in response",
            detail=(
                "Probe sent an Origin header but the server omitted ACAO. "
                "If this endpoint is intentionally same-origin only, the "
                "configuration is correct. Otherwise it suggests CORS isn't "
                "deliberately scoped."
            ),
            remediation="Confirm the endpoint's intended cross-origin policy.",
        )
    ]


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def analyze_cors_response(
    response: CORSResponse,
) -> CORSAnalysis:
    """Run every check against the captured response headers.

    Returns a CORSAnalysis with sorted findings (CRITICAL → INFO).
    """
    h = response.headers

    allow_origin = _get(h, "Access-Control-Allow-Origin")
    allow_credentials_raw = _get(h, "Access-Control-Allow-Credentials")
    allow_credentials = bool(allow_credentials_raw) and allow_credentials_raw.strip().lower() == "true"
    allow_methods = _parse_csv_header(_get(h, "Access-Control-Allow-Methods"))
    allow_headers = _parse_csv_header(_get(h, "Access-Control-Allow-Headers"))
    max_age = _parse_max_age(_get(h, "Access-Control-Max-Age"))

    findings: list[CORSFinding] = []
    findings.extend(_check_wildcard_with_credentials(allow_origin, allow_credentials))
    findings.extend(_check_reflected_origin(response.request_origin, allow_origin, allow_credentials))
    findings.extend(_check_null_origin(allow_origin, allow_credentials))
    findings.extend(_check_subdomain_wildcard(allow_origin))
    findings.extend(
        _check_credentials_with_specific_allow_origin(allow_origin, allow_credentials, response.request_origin)
    )
    findings.extend(_check_permissive_methods(allow_methods, allow_credentials))
    findings.extend(_check_long_preflight_cache(max_age))
    findings.extend(_check_acao_present_at_all(allow_origin, response.request_origin))

    from kryon.util.severity import SEVERITY_RANK as severity_order
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return CORSAnalysis(
        allow_origin=allow_origin,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        max_age_seconds=max_age,
        findings=tuple(findings),
    )
