"""F97 — HTTP Security Headers Auditor.

Pure static analysis on response headers. Covers the gap detected
during validation against cashbox.britimp.com.py — that target
exposed 6 missing-security-header findings (CSP, HSTS, X-Content-Type-
Options, X-Frame-Options, Referrer-Policy, Server-version-leak) that
no specific Kryon validator (CORS, JWT, FAPI, BOLA, ...) was looking
for. F97 fills the equivalent of Mozilla Observatory + securityheaders
.com inside the Kryon stack.

The 18 rules are distributed across five groups:

  Group A — Content Security Policy (HSH-001..005)
  Group B — Transport Security      (HSH-010..013)
  Group C — Basic protections       (HSH-020..023)
  Group D — Cross-Origin isolation  (HSH-030..032)
  Group E — Info leaks              (HSH-040..041)

Banca-safety:
  - PURE static analysis. No HTTP, no I/O, no network. The operator
    probes the target with curl / requests / whatever they prefer
    and hands the response headers + the `is_https` flag to the
    analyzer.
  - Same finding shape as F87.5 JWT / F95 webhook / F87.6 CORS so
    the F89.1 SARIF reporter publishes them unchanged.
  - HSH-010 (HSTS missing) fires only when `is_https=True` — a plain
    HTTP endpoint without HSTS is a different class of problem
    (insecure transport entirely).
  - Conservative parsers: regex only on top-level CSP directives,
    no nested-eval games. Exotic CSP configurations surface as
    "manual review" not false-positive walls.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


__all__ = [
    "HTTPResponse",
    "HSHFinding",
    "SecurityHeadersAnalysis",
    "analyze_security_headers",
    "ALL_HSH_RULES",
]


# Stable rule IDs. Pinned by test.
ALL_HSH_RULES: frozenset[str] = frozenset(
    {
        # Group A — CSP
        "HSH-001",
        "HSH-002",
        "HSH-003",
        "HSH-004",
        "HSH-005",
        # Group B — Transport
        "HSH-010",
        "HSH-011",
        "HSH-012",
        "HSH-013",
        # Group C — Basic
        "HSH-020",
        "HSH-021",
        "HSH-022",
        "HSH-023",
        # Group D — Cross-Origin isolation
        "HSH-030",
        "HSH-031",
        "HSH-032",
        # Group E — Info leaks
        "HSH-040",
        "HSH-041",
    }
)


# HSTS minimum max-age. Mozilla + Google preload-list require 6 months.
_MIN_HSTS_MAX_AGE_SECONDS = 15_768_000  # 6 months in seconds (365.25/2 * 86400)

# Servers that advertise version after "/" — `nginx/1.18.0`, `Apache/
# 2.4.41 (Ubuntu)`, `Microsoft-IIS/10.0`. Plain `nginx` (no slash) is
# not version-leaky.
_SERVER_VERSION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\s*/\s*\d", re.IGNORECASE)

# Headers that fingerprint the underlying stack. Presence is the
# finding; we don't inspect their values.
_FINGERPRINT_HEADERS = (
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HTTPResponse:
    """An inbound HTTP response captured by the operator's probe.
    Only the response headers + transport flag are needed; we don't
    care about the body."""

    url: str = ""
    method: str = "GET"
    is_https: bool = True
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HSHFinding:
    """One detected security-header weakness. Same shape as
    F87.5 JWT / F95 webhook / F87.6 CORS."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str


@dataclass(frozen=True)
class SecurityHeadersAnalysis:
    """Aggregated analysis."""

    csp_present: bool
    hsts_present: bool
    findings: tuple[HSHFinding, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Header lookup
# ---------------------------------------------------------------------------


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive lookup. RFC 7230 §3.2: header names are
    case-insensitive."""
    if not headers:
        return None
    lower = {k.lower(): v for k, v in headers.items()}
    return lower.get(name.lower())


def _parse_csp_directives(csp: str) -> dict[str, list[str]]:
    """Split a CSP value into directive → source list.

    `default-src 'self'; script-src 'self' https://cdn.example.com 'unsafe-inline'`
    → {'default-src': ["'self'"], 'script-src': ["'self'", 'https://cdn.example.com', "'unsafe-inline'"]}

    Conservative: we tokenize by whitespace and don't try to handle
    exotic source expressions. Good enough for the static patterns
    F97 detects."""
    out: dict[str, list[str]] = {}
    if not csp:
        return out
    for raw_directive in csp.split(";"):
        cleaned = raw_directive.strip()
        if not cleaned:
            continue
        parts = cleaned.split()
        if not parts:
            continue
        directive = parts[0].lower()
        sources = parts[1:]
        out[directive] = sources
    return out


def _parse_hsts_directives(hsts: str) -> dict[str, str | bool]:
    """Parse HSTS into directives. `max-age=31536000; includeSubDomains;
    preload` → {'max-age': '31536000', 'includesubdomains': True,
    'preload': True}. Case-insensitive on directive names."""
    out: dict[str, str | bool] = {}
    if not hsts:
        return out
    for raw in hsts.split(";"):
        cleaned = raw.strip()
        if not cleaned:
            continue
        if "=" in cleaned:
            key, _, value = cleaned.partition("=")
            out[key.strip().lower()] = value.strip()
        else:
            out[cleaned.lower()] = True
    return out


# ---------------------------------------------------------------------------
# Group A — Content Security Policy
# ---------------------------------------------------------------------------


def _check_csp(response: HTTPResponse) -> list[HSHFinding]:
    findings: list[HSHFinding] = []
    csp = _get_header(response.headers, "Content-Security-Policy")
    if not csp:
        findings.append(
            HSHFinding(
                rule_id="HSH-001",
                severity="HIGH",
                title="Content-Security-Policy header missing",
                detail=(
                    "No Content-Security-Policy header. The browser will execute "
                    "any inline / external script the document references — XSS "
                    "payloads, malicious tag-manager containers, and supply-chain "
                    "compromises all have free rein."
                ),
                remediation=(
                    "Deploy a CSP with at minimum `default-src 'self'; script-src "
                    "'self' https://trusted.cdn`. Use `nonce-...` or `sha256-...` "
                    "to permit specific inline scripts without `'unsafe-inline'`."
                ),
            )
        )
        return findings  # the rest of the CSP checks are moot without a CSP

    directives = _parse_csp_directives(csp)

    # HSH-002: 'unsafe-inline' in script-src / default-src
    risky_directive = directives.get("script-src") or directives.get("default-src", [])
    if "'unsafe-inline'" in risky_directive:
        findings.append(
            HSHFinding(
                rule_id="HSH-002",
                severity="HIGH",
                title="CSP allows 'unsafe-inline' for scripts",
                detail=(
                    "script-src includes 'unsafe-inline'. XSS payloads can execute "
                    "via inline <script> tags or inline event handlers. The CSP is "
                    "effectively decorative."
                ),
                remediation=(
                    "Remove 'unsafe-inline'. Move inline scripts to external files "
                    "or use nonce-/hash-based allow-listing."
                ),
            )
        )

    # HSH-003: 'unsafe-eval'
    all_sources_flat: list[str] = []
    for sources in directives.values():
        all_sources_flat.extend(sources)
    if "'unsafe-eval'" in all_sources_flat:
        findings.append(
            HSHFinding(
                rule_id="HSH-003",
                severity="MEDIUM",
                title="CSP allows 'unsafe-eval'",
                detail=(
                    "CSP includes 'unsafe-eval'. eval() / new Function() / setTimeout"
                    "(string-arg) can transform untrusted data into executable code."
                ),
                remediation=(
                    "Remove 'unsafe-eval'. Audit JavaScript for eval/Function "
                    "usage; most modern libraries provide eval-free alternatives."
                ),
            )
        )

    # HSH-004: wildcard (*) in script-src or default-src
    if "*" in (directives.get("script-src") or []) or "*" in (directives.get("default-src") or []):
        findings.append(
            HSHFinding(
                rule_id="HSH-004",
                severity="HIGH",
                title="CSP uses wildcard (*) for script source",
                detail=(
                    "script-src or default-src contains *. Any origin can host "
                    "scripts the page will execute. CSP is effectively disabled."
                ),
                remediation=(
                    "Enumerate the specific origins that need script execution. "
                    "Use nonce-based allow-listing if origins are not stable."
                ),
            )
        )

    # HSH-005: http: scheme in CSP sources (mixed content)
    for source in all_sources_flat:
        if source.lower().startswith("http:"):
            findings.append(
                HSHFinding(
                    rule_id="HSH-005",
                    severity="MEDIUM",
                    title="CSP permits http: sources (mixed content)",
                    detail=(
                        f"CSP source {source!r} uses http://. Even with HTTPS on "
                        "the page, allowing http: sources permits MITM-injectable "
                        "resources to be loaded."
                    ),
                    remediation="Replace http: sources with https:; update upstream URLs.",
                )
            )
            break  # one finding per response — list every http: source overwhelms reports

    return findings


# ---------------------------------------------------------------------------
# Group B — Transport Security (HSTS)
# ---------------------------------------------------------------------------


def _check_hsts(response: HTTPResponse) -> list[HSHFinding]:
    findings: list[HSHFinding] = []
    if not response.is_https:
        return findings  # HSTS over plain HTTP is meaningless

    hsts = _get_header(response.headers, "Strict-Transport-Security")
    if not hsts:
        findings.append(
            HSHFinding(
                rule_id="HSH-010",
                severity="HIGH",
                title="Strict-Transport-Security header missing",
                detail=(
                    "HTTPS endpoint without HSTS. First-visit requests can be "
                    "downgraded to HTTP by an active MITM (SSLstrip family). "
                    "Subsequent visits inherit the attacker's session."
                ),
                remediation=(
                    "Add `Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains` (1 year). Submit to hstspreload.org "
                    "after validating subdomain coverage."
                ),
            )
        )
        return findings

    directives = _parse_hsts_directives(hsts)

    # HSH-011: max-age too short
    max_age_raw = directives.get("max-age")
    if isinstance(max_age_raw, str):
        try:
            max_age = int(max_age_raw)
            if max_age < _MIN_HSTS_MAX_AGE_SECONDS:
                findings.append(
                    HSHFinding(
                        rule_id="HSH-011",
                        severity="MEDIUM",
                        title=f"HSTS max-age too short ({max_age}s)",
                        detail=(
                            f"max-age={max_age} (~{max_age // 86400} days). The "
                            f"preload list and Mozilla guidance require ≥{_MIN_HSTS_MAX_AGE_SECONDS}s "
                            "(6 months). Short windows leave the user vulnerable "
                            "after cache expiry."
                        ),
                        remediation=(
                            "Raise max-age to at least 15768000 (6 months); "
                            "31536000 (1 year) is the production-recommended value."
                        ),
                    )
                )
        except (ValueError, TypeError):
            pass

    # HSH-012: includeSubDomains missing
    if "includesubdomains" not in directives:
        findings.append(
            HSHFinding(
                rule_id="HSH-012",
                severity="LOW",
                title="HSTS missing includeSubDomains",
                detail=(
                    "HSTS doesn't cover subdomains. A vulnerable subdomain "
                    "(e.g. dev / staging on the same parent) can be used to "
                    "set cookies the browser sends to the main site over HTTP."
                ),
                remediation=("Add `includeSubDomains`. Audit that ALL subdomains support HTTPS before deploying."),
            )
        )

    # HSH-013: preload not requested
    if "preload" not in directives:
        findings.append(
            HSHFinding(
                rule_id="HSH-013",
                severity="INFO",
                title="HSTS preload not requested",
                detail=(
                    "Without `preload`, the FIRST visit to the domain isn't "
                    "protected from downgrade. The preload list bakes the HSTS "
                    "promise into the browser binary."
                ),
                remediation=(
                    "Once max-age ≥ 31536000 AND includeSubDomains is set AND "
                    "all subdomains support HTTPS, add `preload` and submit to "
                    "hstspreload.org."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Group C — Basic protections
# ---------------------------------------------------------------------------


def _check_basic_protections(response: HTTPResponse) -> list[HSHFinding]:
    findings: list[HSHFinding] = []
    headers = response.headers

    # HSH-020: X-Content-Type-Options
    xcto = _get_header(headers, "X-Content-Type-Options")
    if not xcto or xcto.strip().lower() != "nosniff":
        findings.append(
            HSHFinding(
                rule_id="HSH-020",
                severity="MEDIUM",
                title="X-Content-Type-Options missing or not 'nosniff'",
                detail=(
                    "Browsers may MIME-sniff the response content type. A "
                    "user-uploaded file served with the wrong Content-Type "
                    "could execute as a script."
                ),
                remediation="Add `X-Content-Type-Options: nosniff` globally.",
            )
        )

    # HSH-021: clickjacking — X-Frame-Options ABSENT and CSP frame-ancestors absent
    xfo = _get_header(headers, "X-Frame-Options")
    csp = _get_header(headers, "Content-Security-Policy") or ""
    csp_directives = _parse_csp_directives(csp)
    has_frame_ancestors = "frame-ancestors" in csp_directives
    if not xfo and not has_frame_ancestors:
        findings.append(
            HSHFinding(
                rule_id="HSH-021",
                severity="MEDIUM",
                title="No clickjacking protection (X-Frame-Options + CSP frame-ancestors both missing)",
                detail=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                    "An attacker page can embed this site in an iframe and trick "
                    "users into clicking authenticated controls (clickjacking)."
                ),
                remediation=(
                    "Add `X-Frame-Options: DENY` OR — preferred — "
                    "`Content-Security-Policy: frame-ancestors 'none'` (frame-"
                    "ancestors is the modern equivalent and accepts source lists)."
                ),
            )
        )

    # HSH-022: Referrer-Policy
    referrer = _get_header(headers, "Referrer-Policy")
    if not referrer or referrer.strip().lower() == "unsafe-url":
        findings.append(
            HSHFinding(
                rule_id="HSH-022",
                severity="MEDIUM",
                title="Referrer-Policy missing or unsafe-url",
                detail=(
                    "Without an explicit Referrer-Policy the browser defaults "
                    "to no-referrer-when-downgrade — outbound links leak the "
                    "full URL (potentially including tokens in the path) on "
                    "same-protocol navigations."
                ),
                remediation=(
                    "Add `Referrer-Policy: strict-origin-when-cross-origin` for "
                    "the strictest baseline that still allows analytics. "
                    "`no-referrer` is even tighter if outbound referrer is "
                    "never needed."
                ),
            )
        )

    # HSH-023: Permissions-Policy
    perms = _get_header(headers, "Permissions-Policy")
    if not perms:
        findings.append(
            HSHFinding(
                rule_id="HSH-023",
                severity="LOW",
                title="Permissions-Policy missing",
                detail=(
                    "Without Permissions-Policy (formerly Feature-Policy), "
                    "embedded iframes can access camera, microphone, geolocation, "
                    "etc. with the user's prior grant to your origin."
                ),
                remediation=(
                    "Add `Permissions-Policy: camera=(), microphone=(), "
                    "geolocation=()` (deny by default; whitelist explicitly)."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Group D — Cross-Origin isolation
# ---------------------------------------------------------------------------


def _check_cross_origin(response: HTTPResponse) -> list[HSHFinding]:
    findings: list[HSHFinding] = []
    headers = response.headers
    if not _get_header(headers, "Cross-Origin-Opener-Policy"):
        findings.append(
            HSHFinding(
                rule_id="HSH-030",
                severity="LOW",
                title="Cross-Origin-Opener-Policy missing",
                detail=(
                    "Without COOP, cross-origin windows opened via window.open() "
                    "share browsing context group references. Spectre-class "
                    "side channels and tab-napping become possible."
                ),
                remediation=("Add `Cross-Origin-Opener-Policy: same-origin` for authenticated pages."),
            )
        )
    if not _get_header(headers, "Cross-Origin-Resource-Policy"):
        findings.append(
            HSHFinding(
                rule_id="HSH-031",
                severity="LOW",
                title="Cross-Origin-Resource-Policy missing",
                detail=(
                    "Without CORP, this resource can be embedded by any "
                    "cross-origin document. Side-channel extraction of pixel "
                    "data / response body via timing oracles becomes feasible."
                ),
                remediation=(
                    "Add `Cross-Origin-Resource-Policy: same-origin` (or `same-site` for shared-CDN scenarios)."
                ),
            )
        )
    if not _get_header(headers, "Cross-Origin-Embedder-Policy"):
        findings.append(
            HSHFinding(
                rule_id="HSH-032",
                severity="INFO",
                title="Cross-Origin-Embedder-Policy missing",
                detail=(
                    "COEP is required to enable cross-origin isolation features "
                    "(SharedArrayBuffer, high-res timers). Absence is acceptable "
                    "for most banking apps; surfaces so the auditor knows."
                ),
                remediation=(
                    "Add `Cross-Origin-Embedder-Policy: require-corp` when COI is needed; harmless to omit otherwise."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Group E — Info leaks
# ---------------------------------------------------------------------------


def _check_info_leaks(response: HTTPResponse) -> list[HSHFinding]:
    findings: list[HSHFinding] = []
    headers = response.headers

    # HSH-040: Server header carries version
    server = _get_header(headers, "Server")
    if server and _SERVER_VERSION_RE.match(server.strip()):
        findings.append(
            HSHFinding(
                rule_id="HSH-040",
                severity="LOW",
                title=f"Server header carries version ({server!r})",
                detail=(
                    f"Server: {server!r} reveals software + version. Attackers "
                    "match against CVE databases to find applicable exploits "
                    "without needing to probe."
                ),
                remediation=(
                    "Strip version info. nginx: `server_tokens off;`. Apache: "
                    "`ServerTokens Prod`. Cloudflare / front proxies often "
                    "rewrite Server."
                ),
            )
        )

    # HSH-041: Fingerprint headers
    for header_name in _FINGERPRINT_HEADERS:
        value = _get_header(headers, header_name)
        if value:
            findings.append(
                HSHFinding(
                    rule_id="HSH-041",
                    severity="LOW",
                    title=f"Stack fingerprint header present ({header_name}: {value!r})",
                    detail=(
                        f"{header_name} reveals the underlying framework. Attackers use this for targeted CVE matching."
                    ),
                    remediation=(f"Remove the {header_name} header at the framework or front-proxy level."),
                )
            )
            break  # one fingerprint finding is enough signal
    return findings


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def analyze_security_headers(response: HTTPResponse) -> SecurityHeadersAnalysis:
    """Run every check against the response headers.

    Returns a SecurityHeadersAnalysis with findings sorted by
    severity (CRITICAL → INFO).
    """
    findings: list[HSHFinding] = []
    findings.extend(_check_csp(response))
    findings.extend(_check_hsts(response))
    findings.extend(_check_basic_protections(response))
    findings.extend(_check_cross_origin(response))
    findings.extend(_check_info_leaks(response))

    from kryon.util.severity import SEVERITY_RANK as severity_order

    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id))

    return SecurityHeadersAnalysis(
        csp_present=_get_header(response.headers, "Content-Security-Policy") is not None,
        hsts_present=_get_header(response.headers, "Strict-Transport-Security") is not None,
        findings=tuple(findings),
    )
