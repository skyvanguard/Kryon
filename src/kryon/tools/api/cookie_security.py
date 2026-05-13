"""F98 — Cookie Security Auditor.

Banking is cookie-centric: every session attaches to a cookie that
must carry the right flags or any XSS / CSRF / network downgrade
trivially escalates to session hijack. The failure modes are well-
documented (RFC 6265bis + OWASP Session Management Cheat Sheet) but
consistently missed in production deployments.

This module performs PURE STATIC ANALYSIS on Set-Cookie headers.
Caller probes the target (typically post-login or post-XSRF-token-
emit), captures all Set-Cookie response headers, hands them to the
analyzer. No HTTP, no I/O.

15 rules across 5 groups (stable COOKIE-NNN IDs):

  Group A — Transport flags (HIGH / MEDIUM)
    COOKIE-001  Secure missing on HTTPS
    COOKIE-002  HttpOnly missing on session-named cookie (XSS → hijack)
    COOKIE-003  SameSite attribute missing
    COOKIE-004  SameSite=None without Secure (browser rejection)

  Group B — Scope (LOW)
    COOKIE-005  Domain= sends parent-domain-wide (over-share)
    COOKIE-006  Path=/ sends to every path (under-scoped)

  Group C — Lifetime (HIGH / MEDIUM / INFO)
    COOKIE-010  Session-named cookie with long Expires (>2h)
    COOKIE-011  Session-named cookie missing security flags
    COOKIE-050  Cookie without Max-Age nor Expires (session-only —
                documenting, not necessarily wrong)

  Group D — Framework / value hygiene (MEDIUM / LOW)
    COOKIE-020  Cookie name leaks framework (PHPSESSID, JSESSIONID,
                ASP.NET_SessionId, connect.sid, ...)
    COOKIE-021  Cookie value looks like an unencrypted human identifier

  Group E — RFC 6265bis cookie prefixes (HIGH / MEDIUM)
    COOKIE-030  __Host- prefix violation (missing Secure or Path=/
                or with Domain=)
    COOKIE-031  __Secure- prefix without Secure flag
    COOKIE-040  Multiple Set-Cookie with same name (collision risk)

Banca-safety:
  - PURE static. No HTTP, no I/O, no network. Caller's probe is the
    only thing touching the wire.
  - Same finding shape as F97 / F87.5 JWT / F95 webhook / F87.6 CORS:
    rule_id + severity + title + detail + remediation. F89.1 SARIF
    reporter publishes them unchanged.
  - is_https flag suppresses COOKIE-001 on plain HTTP (different
    class of problem entirely).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


__all__ = [
    "ParsedCookie",
    "CookieFinding",
    "CookieAnalysis",
    "parse_set_cookie",
    "analyze_cookies",
    "ALL_COOKIE_RULES",
    "SESSION_NAME_PATTERNS",
    "FRAMEWORK_COOKIE_NAMES",
]


# Stable rule IDs.
ALL_COOKIE_RULES: frozenset[str] = frozenset(
    {
        "COOKIE-001", "COOKIE-002", "COOKIE-003", "COOKIE-004",
        "COOKIE-005", "COOKIE-006",
        "COOKIE-010", "COOKIE-011",
        "COOKIE-020", "COOKIE-021",
        "COOKIE-030", "COOKIE-031",
        "COOKIE-040",
        "COOKIE-050",
    }
)


# Names that strongly suggest a session / auth / CSRF cookie. We
# match these case-insensitively as substring matches against the
# cookie name. Conservative — false positives here cause noise but
# never silent miss of an obvious session cookie.
SESSION_NAME_PATTERNS: tuple[str, ...] = (
    "session",
    "sess",
    "auth",
    "token",
    "jwt",
    "csrf",
    "xsrf",
    "sid",
    "userid",
    "login",
)


# Framework-fingerprinting cookie names. Their PRESENCE tells the
# attacker which backend stack runs. Exact-match (case-insensitive)
# so substring noise doesn't cause false positives.
FRAMEWORK_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        "phpsessid",       # PHP
        "jsessionid",      # Java servlet
        "asp.net_sessionid",  # ASP.NET
        "asp.netcore.session",  # ASP.NET Core
        "connect.sid",     # Express / Connect
        "laravel_session",  # Laravel
        "ci_session",      # CodeIgniter
        "ci_cookie",
        "djangosession",
        "django_session",
        "django_language",
        "wp-settings",     # WordPress
        "wordpress_logged_in",
        "rack.session",    # Ruby Rack
        "_session_id",     # Rails default
    }
)


# Session-cookie lifetime threshold. Per OWASP Session Management
# Cheat Sheet: idle timeout should be 15-30 min, absolute timeout
# 2-8 hours depending on app. We use 2h (7200s) as the line: longer
# than that on a session-named cookie triggers COOKIE-010.
_SESSION_MAX_LIFETIME_SECONDS = 7200


# Regex for cookie values that look like human-readable identifiers
# (emails, simple usernames, common ID-shapes). Matches HIGH false-
# positive risk — only fires on session-named cookies.
_HUMAN_READABLE_PATTERNS = (
    re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"),  # email
    re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,30}$"),  # plain username-shape
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedCookie:
    """One parsed Set-Cookie header value.

    Booleans (secure / http_only) reflect attribute PRESENCE — values
    after `=` go into the named fields."""

    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    expires: str | None = None  # raw string; we don't parse dates
    max_age: int | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None  # "Lax" | "Strict" | "None" | None
    # The raw Set-Cookie line — useful for the report when we want to
    # echo the exact wire format. Never persisted in findings beyond
    # short fingerprint summaries.
    raw_header: str = ""


@dataclass(frozen=True)
class CookieFinding:
    """One detected weakness. Same shape as F97 HSHFinding."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str
    cookie_name: str = ""  # for report grouping


@dataclass(frozen=True)
class CookieAnalysis:
    """Aggregated analysis."""

    cookie_count: int
    cookies: tuple[ParsedCookie, ...] = field(default_factory=tuple)
    findings: tuple[CookieFinding, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Set-Cookie parser
# ---------------------------------------------------------------------------


def _parse_max_age(value: str) -> int | None:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def parse_set_cookie(header_value: str) -> ParsedCookie | None:
    """Parse ONE Set-Cookie header line.

    Format: `name=value; Attribute=Value; FlagAttribute; ...`. Returns
    None when the header doesn't carry a valid `name=value` pair
    (e.g. empty header, no `=`).

    Defensive throughout: malformed attributes are silently skipped
    rather than raised — a server returning weird Set-Cookie should
    produce findings, not crash the auditor."""
    if not header_value or "=" not in header_value:
        return None
    raw = header_value.strip()

    # The cookie name=value is the FIRST pair; subsequent pairs are
    # attributes. Split on `;` and process the first segment as the
    # name=value carrier.
    segments = [s.strip() for s in raw.split(";") if s.strip()]
    if not segments:
        return None
    first = segments[0]
    if "=" not in first:
        return None
    name, _, value = first.partition("=")
    name = name.strip()
    value = value.strip()
    if not name:
        return None

    # Process remaining segments as attributes.
    domain: str | None = None
    path: str | None = None
    expires: str | None = None
    max_age: int | None = None
    secure = False
    http_only = False
    same_site: str | None = None

    for seg in segments[1:]:
        if "=" in seg:
            attr_name, _, attr_value = seg.partition("=")
            attr_lower = attr_name.strip().lower()
            attr_value = attr_value.strip()
            if attr_lower == "domain":
                domain = attr_value
            elif attr_lower == "path":
                path = attr_value
            elif attr_lower == "expires":
                expires = attr_value
            elif attr_lower == "max-age":
                max_age = _parse_max_age(attr_value)
            elif attr_lower == "samesite":
                same_site = attr_value
        else:
            flag = seg.strip().lower()
            if flag == "secure":
                secure = True
            elif flag == "httponly":
                http_only = True

    return ParsedCookie(
        name=name,
        value=value,
        domain=domain,
        path=path,
        expires=expires,
        max_age=max_age,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        raw_header=raw,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _looks_session_named(name: str) -> bool:
    """Case-insensitive substring match against SESSION_NAME_PATTERNS."""
    lower = name.lower()
    return any(p in lower for p in SESSION_NAME_PATTERNS)


def _looks_framework_named(name: str) -> bool:
    return name.lower() in FRAMEWORK_COOKIE_NAMES


# ---------------------------------------------------------------------------
# Per-cookie checks
# ---------------------------------------------------------------------------


def _check_secure_flag(cookie: ParsedCookie, *, is_https: bool) -> list[CookieFinding]:
    if not is_https:
        return []
    if cookie.secure:
        return []
    return [
        CookieFinding(
            rule_id="COOKIE-001",
            severity="HIGH",
            title=f"Cookie {cookie.name!r} missing Secure flag on HTTPS",
            detail=(
                f"Cookie {cookie.name!r} has no Secure attribute. The browser "
                "will send it over plain HTTP if the user navigates to an HTTP "
                "page on the same origin (rare on banking apps but possible "
                "via misconfigured links / mixed-content fallbacks)."
            ),
            remediation=(
                "Add `Secure` attribute to every Set-Cookie on HTTPS-only sites."
            ),
            cookie_name=cookie.name,
        )
    ]


def _check_http_only(cookie: ParsedCookie) -> list[CookieFinding]:
    if not _looks_session_named(cookie.name):
        return []
    if cookie.http_only:
        return []
    return [
        CookieFinding(
            rule_id="COOKIE-002",
            severity="HIGH",
            title=f"Session cookie {cookie.name!r} missing HttpOnly",
            detail=(
                f"Cookie {cookie.name!r} appears session-related but lacks "
                "HttpOnly. A successful XSS extracts the cookie via "
                "document.cookie — session hijack."
            ),
            remediation=(
                "Add `HttpOnly` to every cookie that carries authentication "
                "state. CSRF tokens deliberately exposed to JS are the "
                "exception — document the exemption per cookie."
            ),
            cookie_name=cookie.name,
        )
    ]


def _check_samesite(cookie: ParsedCookie) -> list[CookieFinding]:
    findings: list[CookieFinding] = []
    if cookie.same_site is None:
        findings.append(
            CookieFinding(
                rule_id="COOKIE-003",
                severity="MEDIUM",
                title=f"Cookie {cookie.name!r} missing SameSite attribute",
                detail=(
                    "Modern browsers default to SameSite=Lax when the attribute "
                    "is absent, but legacy browsers + some bots default to None. "
                    "Explicit is better than implicit for an auth boundary."
                ),
                remediation=(
                    "Add `SameSite=Lax` (or Strict for purely first-party "
                    "session cookies; None for cross-origin SSO with Secure)."
                ),
                cookie_name=cookie.name,
            )
        )
    elif cookie.same_site.lower() == "none" and not cookie.secure:
        findings.append(
            CookieFinding(
                rule_id="COOKIE-004",
                severity="MEDIUM",
                title=f"Cookie {cookie.name!r} has SameSite=None without Secure",
                detail=(
                    "RFC 6265bis + browsers (Chrome 80+) reject `SameSite=None` "
                    "without `Secure`. The cookie effectively won't be set on "
                    "modern browsers and the server's intent is unclear."
                ),
                remediation="Add `Secure` whenever `SameSite=None` is used.",
                cookie_name=cookie.name,
            )
        )
    return findings


def _check_scope(cookie: ParsedCookie) -> list[CookieFinding]:
    findings: list[CookieFinding] = []
    if cookie.domain and cookie.domain.startswith("."):
        findings.append(
            CookieFinding(
                rule_id="COOKIE-005",
                severity="LOW",
                title=f"Cookie {cookie.name!r} has parent-domain scope ({cookie.domain})",
                detail=(
                    f"Domain={cookie.domain}. Sends the cookie to every subdomain "
                    "of the parent. A compromise of any subdomain (dev / staging "
                    "/ legacy app) gains the session credential."
                ),
                remediation=(
                    "Pin Domain= to the exact host. Use the `__Host-` cookie "
                    "prefix for the strongest guarantee (forbids Domain at all)."
                ),
                cookie_name=cookie.name,
            )
        )
    if (cookie.path is None or cookie.path == "/") and _looks_session_named(cookie.name):
        findings.append(
            CookieFinding(
                rule_id="COOKIE-006",
                severity="LOW",
                title=f"Session cookie {cookie.name!r} has Path=/ (every path)",
                detail=(
                    "Session cookies sent to every path mean any page on the "
                    "domain — including static asset endpoints — receives the "
                    "auth credential. Scope to the application path only."
                ),
                remediation=(
                    "Set Path=/app or wherever the authenticated surface lives."
                ),
                cookie_name=cookie.name,
            )
        )
    return findings


def _check_lifetime(cookie: ParsedCookie) -> list[CookieFinding]:
    findings: list[CookieFinding] = []
    if _looks_session_named(cookie.name) and cookie.max_age is not None:
        if cookie.max_age > _SESSION_MAX_LIFETIME_SECONDS:
            findings.append(
                CookieFinding(
                    rule_id="COOKIE-010",
                    severity="MEDIUM",
                    title=f"Session cookie {cookie.name!r} has long Max-Age ({cookie.max_age}s)",
                    detail=(
                        f"Max-Age={cookie.max_age}s "
                        f"(~{cookie.max_age // 3600}h). OWASP guidance is "
                        f"<{_SESSION_MAX_LIFETIME_SECONDS}s ({_SESSION_MAX_LIFETIME_SECONDS // 3600}h) "
                        "absolute timeout for session-bearing cookies."
                    ),
                    remediation=(
                        f"Cap Max-Age at {_SESSION_MAX_LIFETIME_SECONDS}s. "
                        "Implement idle-timeout refresh server-side for active "
                        "sessions."
                    ),
                    cookie_name=cookie.name,
                )
            )

    # COOKIE-011: session-named with completely missing security flags
    if _looks_session_named(cookie.name):
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if not cookie.http_only:
            missing.append("HttpOnly")
        if cookie.same_site is None:
            missing.append("SameSite")
        if len(missing) == 3:
            findings.append(
                CookieFinding(
                    rule_id="COOKIE-011",
                    severity="HIGH",
                    title=f"Session cookie {cookie.name!r} has zero security flags",
                    detail=(
                        f"Cookie {cookie.name!r} appears session-related but "
                        f"lacks ALL of: {', '.join(missing)}. This is the worst-"
                        "case configuration — XSS + MITM + CSRF all in scope."
                    ),
                    remediation=(
                        "Set `Secure; HttpOnly; SameSite=Lax` at minimum. "
                        "Reaudit every session-bearing endpoint."
                    ),
                    cookie_name=cookie.name,
                )
            )

    # COOKIE-050: no Max-Age and no Expires (informational — session cookies
    # are valid, just call it out so the auditor confirms intent).
    if cookie.max_age is None and not cookie.expires:
        findings.append(
            CookieFinding(
                rule_id="COOKIE-050",
                severity="INFO",
                title=f"Cookie {cookie.name!r} has no Max-Age nor Expires (session-only)",
                detail=(
                    "Without Max-Age or Expires, the cookie persists only for "
                    "the browser session. Often intentional; surface so the "
                    "auditor confirms."
                ),
                remediation=(
                    "If session-only is intended, no action. Otherwise set an "
                    "explicit Max-Age."
                ),
                cookie_name=cookie.name,
            )
        )

    return findings


def _check_framework_leak(cookie: ParsedCookie) -> list[CookieFinding]:
    if not _looks_framework_named(cookie.name):
        return []
    return [
        CookieFinding(
            rule_id="COOKIE-020",
            severity="MEDIUM",
            title=f"Cookie name {cookie.name!r} fingerprints the backend framework",
            detail=(
                f"Cookie {cookie.name!r} reveals the underlying framework "
                "(PHP / Java servlet / ASP.NET / Express / Laravel / ...). "
                "Attackers match against CVE databases for targeted exploits."
            ),
            remediation=(
                "Rename to a neutral identifier (e.g. `session_id`, `auth`). "
                "Many frameworks support this via configuration."
            ),
            cookie_name=cookie.name,
        )
    ]


def _check_value_hygiene(cookie: ParsedCookie) -> list[CookieFinding]:
    """COOKIE-021 — only fires on session-named cookies; we don't
    want false positives on tracking cookies that legitimately carry
    user identifiers."""
    if not _looks_session_named(cookie.name):
        return []
    value = cookie.value.strip()
    if not value:
        return []
    for pattern in _HUMAN_READABLE_PATTERNS:
        if pattern.match(value):
            return [
                CookieFinding(
                    rule_id="COOKIE-021",
                    severity="LOW",
                    title=f"Session cookie {cookie.name!r} value looks unencrypted",
                    detail=(
                        f"Cookie value matches a human-readable pattern "
                        "(email / username). Session cookies should be opaque "
                        "tokens — readable values are forgeable + may leak PII."
                    ),
                    remediation=(
                        "Replace with a cryptographic session id (UUID v4, "
                        "32+ bytes random base64). Map server-side to the "
                        "human identifier."
                    ),
                    cookie_name=cookie.name,
                )
            ]
    return []


def _check_prefixes(cookie: ParsedCookie) -> list[CookieFinding]:
    """RFC 6265bis cookie name prefixes:
      - `__Host-`: requires Secure; Path=/; NO Domain attribute.
      - `__Secure-`: requires Secure flag.
    A cookie carrying these prefixes signals INTENT. A misconfigured
    prefix is worse than no prefix — the developer asked for guard
    rails and the server omitted them."""
    findings: list[CookieFinding] = []
    name_lower = cookie.name.lower()

    if name_lower.startswith("__host-"):
        problems = []
        if not cookie.secure:
            problems.append("missing Secure")
        if cookie.path != "/":
            problems.append(f"Path={cookie.path!r} (must be `/`)")
        if cookie.domain is not None:
            problems.append(f"Domain={cookie.domain!r} (forbidden on __Host-)")
        if problems:
            findings.append(
                CookieFinding(
                    rule_id="COOKIE-030",
                    severity="HIGH",
                    title=f"__Host- cookie {cookie.name!r} violates prefix contract",
                    detail=(
                        f"Cookie {cookie.name!r} uses the __Host- prefix but: "
                        f"{', '.join(problems)}. Per RFC 6265bis §4.1.3, "
                        "browsers SHOULD reject prefix-violating cookies — "
                        "the developer's intent (strongest guarantee) is "
                        "defeated."
                    ),
                    remediation=(
                        "Add Secure, set Path=/, remove Domain. Or drop the "
                        "__Host- prefix if any of those are intentional."
                    ),
                    cookie_name=cookie.name,
                )
            )

    elif name_lower.startswith("__secure-"):
        if not cookie.secure:
            findings.append(
                CookieFinding(
                    rule_id="COOKIE-031",
                    severity="HIGH",
                    title=f"__Secure- cookie {cookie.name!r} missing Secure flag",
                    detail=(
                        f"Cookie {cookie.name!r} uses the __Secure- prefix but "
                        "has no Secure attribute. Per RFC 6265bis browsers "
                        "SHOULD reject this. Developer's intent is broken."
                    ),
                    remediation="Add `Secure` or drop the __Secure- prefix.",
                    cookie_name=cookie.name,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Multi-cookie checks
# ---------------------------------------------------------------------------


def _check_duplicates(cookies: list[ParsedCookie]) -> list[CookieFinding]:
    """COOKIE-040 — multiple Set-Cookie with same name. Browsers
    resolve to the LAST one but the behaviour is fragile (path /
    domain qualifiers can change which cookie wins for a request)."""
    findings: list[CookieFinding] = []
    seen: dict[str, int] = {}
    for cookie in cookies:
        seen[cookie.name] = seen.get(cookie.name, 0) + 1
    for name, count in seen.items():
        if count >= 2:
            findings.append(
                CookieFinding(
                    rule_id="COOKIE-040",
                    severity="MEDIUM",
                    title=f"Multiple Set-Cookie headers for {name!r} ({count} occurrences)",
                    detail=(
                        f"Response sets {count} cookies named {name!r}. "
                        "Browsers resolve to the LAST one for matching "
                        "requests, but qualifier differences (Path / Domain) "
                        "make behaviour brittle and order-dependent."
                    ),
                    remediation=(
                        "Set the cookie once with the intended attributes. If "
                        "you need to clear a previous cookie, use Max-Age=0 + "
                        "the same Path/Domain so the browser deletes the "
                        "specific instance."
                    ),
                    cookie_name=name,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def analyze_cookies(
    set_cookie_headers: list[str],
    *,
    is_https: bool = True,
) -> CookieAnalysis:
    """Analyze a list of Set-Cookie header values.

    Args:
        set_cookie_headers: one entry per Set-Cookie line. Servers
            return multiple Set-Cookie headers as separate header
            instances; callers typically extract them with
            `response.headers.get_all("Set-Cookie")` (Python stdlib)
            or `response.raw.headers.getlist("Set-Cookie")` (requests).
        is_https: True when the probe was over HTTPS. COOKIE-001
            fires only on HTTPS responses.

    Returns:
        CookieAnalysis with parsed cookies + sorted findings (CRITICAL
        → INFO).
    """
    cookies: list[ParsedCookie] = []
    for header in set_cookie_headers:
        parsed = parse_set_cookie(header)
        if parsed is not None:
            cookies.append(parsed)

    findings: list[CookieFinding] = []
    for cookie in cookies:
        findings.extend(_check_secure_flag(cookie, is_https=is_https))
        findings.extend(_check_http_only(cookie))
        findings.extend(_check_samesite(cookie))
        findings.extend(_check_scope(cookie))
        findings.extend(_check_lifetime(cookie))
        findings.extend(_check_framework_leak(cookie))
        findings.extend(_check_value_hygiene(cookie))
        findings.extend(_check_prefixes(cookie))

    findings.extend(_check_duplicates(cookies))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id, f.cookie_name))

    return CookieAnalysis(
        cookie_count=len(cookies),
        cookies=tuple(cookies),
        findings=tuple(findings),
    )
