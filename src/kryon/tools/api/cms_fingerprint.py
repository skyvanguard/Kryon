"""F104 — CMS / Framework Fingerprinting.

Static analyzer that identifies the CMS or web framework + (when
detectable) its version from HTTP response headers, HTML body
fingerprints, meta tags, asset paths, and cookies. Then enriches
with known-bad-version rules.

This is reconnaissance-grade detection: useful for prioritizing
exploit lookups (Wordpress < 5.7 = CVE-2021-29447, Drupal < 7.78 =
SA-CORE-2020-013, etc.) and tailoring the rest of the audit
playbook (WordPress sites get wp-admin probing, Joomla gets
/administrator/, etc.).

Stable rule IDs:

  CMS-001  WordPress detected (INFO)
  CMS-002  Drupal detected (INFO)
  CMS-003  Joomla detected (INFO)
  CMS-004  Magento detected (INFO)
  CMS-005  TYPO3 detected (INFO)
  CMS-010  WordPress < 5.7 → CVE-2021-29447 XXE (HIGH)
  CMS-011  WordPress < 5.8.3 → multiple sec patches (MEDIUM)
  CMS-012  Drupal < 7.78 → SA-CORE-2020-013 (HIGH)
  CMS-020  Django detected (INFO)
  CMS-021  Rails detected (INFO)
  CMS-022  ASP.NET detected (INFO)
  CMS-023  Express.js detected (INFO)
  CMS-024  Laravel detected (INFO)
  CMS-025  Spring Boot detected (INFO)
  CMS-026  Flask detected (INFO)
  CMS-030  X-Powered-By header leaks framework version (LOW)
  CMS-031  Server header leaks server version (LOW)
  CMS-040  WordPress version disclosed in HTML meta (LOW)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "FingerprintObservation",
    "FingerprintFinding",
    "FingerprintAnalysis",
    "analyze_fingerprint",
    "ALL_CMS_RULES",
]


ALL_CMS_RULES: frozenset[str] = frozenset(
    {f"CMS-00{n}" for n in range(1, 6)}
    | {f"CMS-01{n}" for n in (0, 1, 2)}
    | {f"CMS-02{n}" for n in range(0, 7)}
    | {"CMS-030", "CMS-031", "CMS-040"}
)


# Header signatures
_HEADER_SIGS: dict[str, tuple[str, str]] = {
    # (rule_id, friendly_name) keyed on lower(header_name)
    "x-powered-by": ("CMS-030", "X-Powered-By"),
    "server": ("CMS-031", "Server"),
    "x-drupal-cache": ("CMS-002", "Drupal"),
    "x-drupal-dynamic-cache": ("CMS-002", "Drupal"),
    "x-generator": ("", ""),  # special: parse value
    "x-aspnet-version": ("CMS-022", "ASP.NET"),
    "x-aspnetmvc-version": ("CMS-022", "ASP.NET"),
}

# Body / meta fingerprint patterns
_BODY_SIGS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("CMS-001", re.compile(r"/wp-content/|/wp-includes/|wp-json", re.IGNORECASE), "WordPress"),
    ("CMS-001", re.compile(r'<meta name="generator"\s+content="WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), "WordPress"),
    ("CMS-002", re.compile(r'<meta name="generator"\s+content="Drupal\s+(\d+(?:\.\d+)?)', re.IGNORECASE), "Drupal"),
    ("CMS-003", re.compile(r'<meta name="generator"\s+content="Joomla', re.IGNORECASE), "Joomla"),
    ("CMS-004", re.compile(r"Magento|Mage\.Cookies", re.IGNORECASE), "Magento"),
    ("CMS-005", re.compile(r"typo3temp|TYPO3", re.IGNORECASE), "TYPO3"),
)

# WP version regex inside generator meta
_WP_VERSION_RE = re.compile(
    r'<meta name="generator"\s+content="WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE
)
_DRUPAL_VERSION_RE = re.compile(
    r'<meta name="generator"\s+content="Drupal\s+(\d+(?:\.\d+)?)', re.IGNORECASE
)


# Cookie name signatures
_COOKIE_SIGS: dict[str, tuple[str, str]] = {
    "wp_": ("CMS-001", "WordPress"),
    "wordpress_logged_in_": ("CMS-001", "WordPress"),
    "drupal.tableDrag.showWeight": ("CMS-002", "Drupal"),
    "drupal_uid": ("CMS-002", "Drupal"),
    "phpsessid": ("", "PHP"),  # too generic on its own
    "jsessionid": ("", "Java"),
    "laravel_session": ("CMS-024", "Laravel"),
    "ci_session": ("", "CodeIgniter"),
    "connect.sid": ("CMS-023", "Express.js"),
    "csrftoken": ("CMS-020", "Django"),
    "django_language": ("CMS-020", "Django"),
    "_session_id": ("CMS-021", "Rails"),
    "asp.net_sessionid": ("CMS-022", "ASP.NET"),
    "xsrf-token": ("CMS-024", "Laravel"),  # also common in others
}


# Path signatures (operator usually doesn't probe but can pass any
# observed paths from the HTML to drive detection)
_PATH_SIGS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("CMS-001", re.compile(r"/wp-(content|includes|admin|json)", re.IGNORECASE), "WordPress"),
    ("CMS-002", re.compile(r"/sites/(?:default|all)/", re.IGNORECASE), "Drupal"),
    ("CMS-003", re.compile(r"/templates/.*?/(?:html|css)", re.IGNORECASE), "Joomla"),
)


# Framework-specific header patterns
_FRAMEWORK_HEADER_PATTERNS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("CMS-020", re.compile(r"Django|django", re.IGNORECASE), "Django"),
    ("CMS-021", re.compile(r"Phusion Passenger|^Rails|Ruby on Rails", re.IGNORECASE), "Rails"),
    ("CMS-022", re.compile(r"ASP\.NET|Microsoft-IIS|Microsoft-HTTPAPI", re.IGNORECASE), "ASP.NET"),
    ("CMS-023", re.compile(r"Express|express", re.IGNORECASE), "Express.js"),
    ("CMS-024", re.compile(r"Laravel|laravel", re.IGNORECASE), "Laravel"),
    ("CMS-025", re.compile(r"Spring|spring", re.IGNORECASE), "Spring Boot"),
    ("CMS-026", re.compile(r"Werkzeug|Flask|gunicorn", re.IGNORECASE), "Flask/Werkzeug"),
)


def _parse_version(text: str) -> tuple[int, ...] | None:
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text.strip())
    if not m:
        return None
    parts = [int(g) for g in m.groups() if g is not None]
    return tuple(parts) if parts else None


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    length = max(len(a), len(b))
    aa = a + (0,) * (length - len(a))
    bb = b + (0,) * (length - len(b))
    return aa < bb


@dataclass(frozen=True)
class FingerprintObservation:
    """Operator-collected evidence."""

    url: str
    headers: tuple[tuple[str, str], ...] = ()  # ((name, value), ...)
    body_snippet: str = ""  # first ~5K chars of HTML
    cookie_names: tuple[str, ...] = ()  # cookie names from Set-Cookie / page JS
    observed_paths: tuple[str, ...] = ()  # paths grepped from HTML (script/link href)


@dataclass(frozen=True)
class FingerprintFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    detected_tech: str = ""
    detected_version: str = ""


@dataclass(frozen=True)
class FingerprintAnalysis:
    url: str
    findings: tuple[FingerprintFinding, ...] = field(default_factory=tuple)


def _find_header(headers: tuple[tuple[str, str], ...], name: str) -> str:
    nlow = name.lower()
    for hname, hval in headers:
        if hname.lower() == nlow:
            return hval
    return ""


def _detect_via_headers(obs: FingerprintObservation) -> list[FingerprintFinding]:
    findings: list[FingerprintFinding] = []
    for hname, hval in obs.headers:
        nlow = hname.lower()
        # CMS-030 / CMS-031 disclosure findings
        if nlow == "x-powered-by" and hval.strip():
            findings.append(
                FingerprintFinding(
                    rule_id="CMS-030",
                    severity="LOW",
                    title=f"X-Powered-By header leaks framework: {hval!r}",
                    detail=(
                        f"Server response includes X-Powered-By: {hval!r}, "
                        "which discloses the framework + often the version. "
                        "Useful reconnaissance for attackers."
                    ),
                    remediation=(
                        "Remove X-Powered-By header. nginx: "
                        "`fastcgi_hide_header X-Powered-By;`. Apache: "
                        "`Header unset X-Powered-By`."
                    ),
                    detected_tech=hval,
                )
            )
        if nlow == "server" and hval.strip() and re.search(r"\d+\.\d+", hval):
            findings.append(
                FingerprintFinding(
                    rule_id="CMS-031",
                    severity="LOW",
                    title=f"Server header leaks server version: {hval!r}",
                    detail=(
                        f"Server response includes Server: {hval!r} which "
                        "discloses the version. Attackers map version → "
                        "known CVE."
                    ),
                    remediation=(
                        "Minimize the Server header. nginx: "
                        "`server_tokens off;`. Apache: "
                        "`ServerTokens Prod` + `ServerSignature Off`."
                    ),
                    detected_tech=hval,
                )
            )
        # Framework detection by header value pattern
        for rule_id, pattern, label in _FRAMEWORK_HEADER_PATTERNS:
            if pattern.search(hval):
                findings.append(
                    FingerprintFinding(
                        rule_id=rule_id,
                        severity="INFO",
                        title=f"{label} detected via {hname} header",
                        detail=f"Header {hname}: {hval!r} matches {label} signature.",
                        remediation=(
                            f"Confirm {label} is on a supported version. "
                            "Keep server software patched."
                        ),
                        detected_tech=label,
                    )
                )
        # Drupal-specific cache headers
        if nlow in ("x-drupal-cache", "x-drupal-dynamic-cache"):
            findings.append(
                FingerprintFinding(
                    rule_id="CMS-002",
                    severity="INFO",
                    title="Drupal detected via cache header",
                    detail=f"Header {hname} present — site runs Drupal.",
                    remediation="Confirm Drupal version is current (Drupal 10+).",
                    detected_tech="Drupal",
                )
            )
        # ASP.NET headers
        if nlow in ("x-aspnet-version", "x-aspnetmvc-version"):
            findings.append(
                FingerprintFinding(
                    rule_id="CMS-022",
                    severity="INFO",
                    title=f"ASP.NET detected via {hname} header",
                    detail=f"{hname}: {hval} — exact framework version disclosed.",
                    remediation=(
                        "Remove X-AspNet-Version. web.config: "
                        "`<httpRuntime enableVersionHeader='false' />`."
                    ),
                    detected_tech="ASP.NET",
                    detected_version=hval,
                )
            )
    return findings


def _detect_via_body(obs: FingerprintObservation) -> list[FingerprintFinding]:
    findings: list[FingerprintFinding] = []
    body = obs.body_snippet or ""
    if not body:
        return findings

    # WordPress
    wp_match = _WP_VERSION_RE.search(body)
    if wp_match:
        version = wp_match.group(1)
        ver_tuple = _parse_version(version)
        findings.append(
            FingerprintFinding(
                rule_id="CMS-001",
                severity="INFO",
                title=f"WordPress {version} detected",
                detail=f"<meta name=generator content='WordPress {version}'> present.",
                remediation="Keep WordPress core + plugins + themes updated.",
                detected_tech="WordPress",
                detected_version=version,
            )
        )
        findings.append(
            FingerprintFinding(
                rule_id="CMS-040",
                severity="LOW",
                title="WordPress version disclosed in HTML meta",
                detail="The generator meta tag reveals the exact WordPress version. Remove it.",
                remediation=(
                    "Hide the generator meta: in functions.php → "
                    "`remove_action('wp_head','wp_generator');`."
                ),
                detected_tech="WordPress",
                detected_version=version,
            )
        )
        # CVE-mapped rules
        if ver_tuple is not None:
            if _lt(ver_tuple, (5, 7, 0)):
                findings.append(
                    FingerprintFinding(
                        rule_id="CMS-010",
                        severity="HIGH",
                        title=f"WordPress {version} is vulnerable to CVE-2021-29447 (XXE)",
                        detail=(
                            "WordPress media-library XXE via media-handling on "
                            "PHP 8. Authenticated attacker can exfil files."
                        ),
                        remediation="Upgrade WordPress to 5.7+ immediately.",
                        detected_tech="WordPress",
                        detected_version=version,
                    )
                )
            if _lt(ver_tuple, (5, 8, 3)):
                findings.append(
                    FingerprintFinding(
                        rule_id="CMS-011",
                        severity="MEDIUM",
                        title=f"WordPress {version} missing recent security fixes",
                        detail=(
                            "Multiple SQL-i + XSS + auth fixes shipped through "
                            "5.8.3. Upgrade to current LTS."
                        ),
                        remediation="Upgrade WordPress core to current supported release.",
                        detected_tech="WordPress",
                        detected_version=version,
                    )
                )
    elif re.search(r"/wp-content/|/wp-includes/|wp-json", body, re.IGNORECASE):
        findings.append(
            FingerprintFinding(
                rule_id="CMS-001",
                severity="INFO",
                title="WordPress detected (no version exposed)",
                detail="Page references /wp-content/ or /wp-includes/ paths.",
                remediation="Confirm version is current.",
                detected_tech="WordPress",
            )
        )

    # Drupal
    drupal_match = _DRUPAL_VERSION_RE.search(body)
    if drupal_match:
        version = drupal_match.group(1)
        ver_tuple = _parse_version(version)
        findings.append(
            FingerprintFinding(
                rule_id="CMS-002",
                severity="INFO",
                title=f"Drupal {version} detected",
                detail=f"<meta name=generator content='Drupal {version}'> present.",
                remediation="Keep Drupal core + contributed modules patched.",
                detected_tech="Drupal",
                detected_version=version,
            )
        )
        if ver_tuple is not None and _lt(ver_tuple, (7, 78)):
            findings.append(
                FingerprintFinding(
                    rule_id="CMS-012",
                    severity="HIGH",
                    title=f"Drupal {version} is vulnerable to SA-CORE-2020-013",
                    detail=(
                        "Drupal < 7.78 / < 8.9.13 / < 9.0.11 → arbitrary PHP "
                        "code via crafted file upload."
                    ),
                    remediation="Upgrade Drupal to a supported release immediately.",
                    detected_tech="Drupal",
                    detected_version=version,
                )
            )

    # Joomla
    if re.search(r'<meta name="generator"\s+content="Joomla', body, re.IGNORECASE):
        findings.append(
            FingerprintFinding(
                rule_id="CMS-003",
                severity="INFO",
                title="Joomla detected",
                detail="Generator meta references Joomla.",
                remediation="Keep Joomla core + extensions updated. Remove generator meta.",
                detected_tech="Joomla",
            )
        )

    # Magento / TYPO3
    if re.search(r"Magento|Mage\.Cookies", body, re.IGNORECASE):
        findings.append(
            FingerprintFinding(
                rule_id="CMS-004",
                severity="INFO",
                title="Magento detected",
                detail="Page references Magento / Mage.Cookies.",
                remediation="Keep Magento patched (Adobe Commerce releases).",
                detected_tech="Magento",
            )
        )
    if re.search(r"typo3temp", body, re.IGNORECASE):
        findings.append(
            FingerprintFinding(
                rule_id="CMS-005",
                severity="INFO",
                title="TYPO3 detected",
                detail="Page references typo3temp/.",
                remediation="Keep TYPO3 patched.",
                detected_tech="TYPO3",
            )
        )

    return findings


def _detect_via_cookies(obs: FingerprintObservation) -> list[FingerprintFinding]:
    findings: list[FingerprintFinding] = []
    for raw_name in obs.cookie_names:
        nlow = raw_name.lower()
        for prefix, (rule_id, label) in _COOKIE_SIGS.items():
            if not rule_id:
                continue
            if nlow.startswith(prefix):
                findings.append(
                    FingerprintFinding(
                        rule_id=rule_id,
                        severity="INFO",
                        title=f"{label} detected via cookie {raw_name!r}",
                        detail=f"Cookie {raw_name} is characteristic of {label}.",
                        remediation="Confirm framework is patched.",
                        detected_tech=label,
                    )
                )
    return findings


def _dedupe(findings: list[FingerprintFinding]) -> list[FingerprintFinding]:
    """Keep only the FIRST finding per (rule_id, detected_tech, version)."""
    seen: set[tuple[str, str, str]] = set()
    out: list[FingerprintFinding] = []
    for f in findings:
        key = (f.rule_id, f.detected_tech, f.detected_version)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def analyze_fingerprint(obs: FingerprintObservation) -> FingerprintAnalysis:
    findings: list[FingerprintFinding] = []
    findings.extend(_detect_via_headers(obs))
    findings.extend(_detect_via_body(obs))
    findings.extend(_detect_via_cookies(obs))
    findings = _dedupe(findings)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id))
    return FingerprintAnalysis(url=obs.url, findings=tuple(findings))
