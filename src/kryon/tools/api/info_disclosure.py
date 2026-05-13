"""F101 — Information Disclosure Scanner.

Universal pre-auth scanner for accidentally-exposed files / paths.
Every web application — banking or otherwise — has the same failure
modes: `.git/config` deployed to the document root, `.env` files
served by a misconfigured nginx, source maps in production, backup
files left by careless ops.

Pure static analysis: the operator probes the target with HEAD/GET
against the path list, captures status codes + body fingerprints,
hands them to the analyzer.

14 rules across 5 groups (stable INFO-NNN IDs):

  Group A — Version control + secrets exposure (CRITICAL / HIGH)
    INFO-001  .git/config / .svn/entries / .hg/store exposed
    INFO-002  .env / .env.local / .env.production exposed
    INFO-003  Database dump exposed (*.sql, dump.sql, backup.sql)

  Group B — Build artifacts (MEDIUM / LOW)
    INFO-010  JavaScript source map exposed (*.js.map)
    INFO-011  CSS source map exposed (*.css.map)
    INFO-012  Backup files (~/.bak/.swp/.old/.orig)
    INFO-013  IDE artifacts (.idea/, .vscode/settings.json)
    INFO-014  Build / config files (Dockerfile, docker-compose.yml,
              package.json, Gemfile, requirements.txt)

  Group C — Server-info pages (HIGH)
    INFO-020  Apache server-status / server-info exposed
    INFO-021  phpinfo() page exposed

  Group D — Admin / management interfaces (MEDIUM)
    INFO-030  CMS admin path responds (wp-admin, /administrator,
              /admin)
    INFO-031  Database management UI (phpmyadmin, adminer)

  Group E — Documentation leakage (LOW / INFO)
    INFO-040  API docs (swagger, /api-docs, /openapi.json)
    INFO-050  Robots.txt with suspicious disallowed paths

Banca-safety: same finding shape as F97/F98/F100. PURE static.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "DisclosureProbe",
    "DisclosureFinding",
    "DisclosureAnalysis",
    "analyze_probes",
    "default_probe_paths",
    "ALL_DISCLOSURE_RULES",
]


ALL_DISCLOSURE_RULES: frozenset[str] = frozenset(
    {
        "INFO-001", "INFO-002", "INFO-003",
        "INFO-010", "INFO-011", "INFO-012", "INFO-013", "INFO-014",
        "INFO-020", "INFO-021",
        "INFO-030", "INFO-031",
        "INFO-040", "INFO-050",
    }
)


# Map each probe path to (rule_id, severity, title, signature-regex).
# Signature regex inspects the body fingerprint (first 200 chars
# from response) to confirm the response is the real artifact,
# not a generic 200 OK from a SPA that serves the same shell for
# every path.
_PROBE_TABLE: dict[str, tuple[str, str, str, re.Pattern]] = {
    # INFO-001: version control
    "/.git/config": ("INFO-001", "CRITICAL", "Git config file exposed",
                     re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE)),
    "/.git/HEAD": ("INFO-001", "CRITICAL", "Git HEAD file exposed",
                   re.compile(r"^ref:\s+refs/", re.IGNORECASE | re.MULTILINE)),
    "/.svn/entries": ("INFO-001", "HIGH", "SVN entries file exposed",
                      re.compile(r"^\d+\s*$", re.MULTILINE)),
    "/.hg/store": ("INFO-001", "HIGH", "Mercurial store directory exposed",
                   re.compile(r"00manifest|index", re.IGNORECASE)),
    # INFO-002: env files
    "/.env": ("INFO-002", "CRITICAL", ".env file exposed",
              re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.production": ("INFO-002", "CRITICAL", ".env.production file exposed",
                         re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.local": ("INFO-002", "CRITICAL", ".env.local file exposed",
                    re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    # INFO-003: db dumps
    "/dump.sql": ("INFO-003", "CRITICAL", "Database dump file exposed",
                  re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.IGNORECASE)),
    "/backup.sql": ("INFO-003", "CRITICAL", "Database backup file exposed",
                    re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.IGNORECASE)),
    "/database.sql": ("INFO-003", "CRITICAL", "Database SQL exposed",
                      re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.IGNORECASE)),
    # INFO-013: IDE
    "/.idea/workspace.xml": ("INFO-013", "MEDIUM", "JetBrains IDE workspace exposed",
                             re.compile(r"<project|<component", re.IGNORECASE)),
    "/.vscode/settings.json": ("INFO-013", "LOW", "VS Code settings exposed",
                               re.compile(r"\{|editor\.", re.IGNORECASE)),
    "/.DS_Store": ("INFO-013", "LOW", "macOS Finder metadata exposed",
                   re.compile(r"Bud1|DSDB", re.IGNORECASE)),
    # INFO-014: build files
    "/Dockerfile": ("INFO-014", "MEDIUM", "Dockerfile exposed",
                    re.compile(r"^(FROM|RUN|COPY|ENV)", re.IGNORECASE | re.MULTILINE)),
    "/docker-compose.yml": ("INFO-014", "MEDIUM", "Docker Compose config exposed",
                            re.compile(r"^services:|^version:", re.IGNORECASE | re.MULTILINE)),
    "/package.json": ("INFO-014", "LOW", "Node.js package manifest exposed",
                      re.compile(r'"name"|"version"|"dependencies"', re.IGNORECASE)),
    "/composer.json": ("INFO-014", "LOW", "PHP Composer manifest exposed",
                       re.compile(r'"name"|"require"', re.IGNORECASE)),
    "/requirements.txt": ("INFO-014", "LOW", "Python requirements exposed",
                          re.compile(r"^[a-zA-Z0-9_-]+[=<>~!]+", re.MULTILINE)),
    "/Gemfile": ("INFO-014", "LOW", "Ruby Gemfile exposed",
                 re.compile(r"^source\s+|^gem\s+", re.IGNORECASE | re.MULTILINE)),
    # INFO-020: server status
    "/server-status": ("INFO-020", "HIGH", "Apache server-status exposed",
                       re.compile(r"Apache.*Status|Server uptime", re.IGNORECASE)),
    "/server-info": ("INFO-020", "HIGH", "Apache server-info exposed",
                     re.compile(r"Apache Server Information", re.IGNORECASE)),
    # INFO-021: phpinfo
    "/phpinfo.php": ("INFO-021", "HIGH", "phpinfo() exposed",
                     re.compile(r"PHP Version|phpinfo", re.IGNORECASE)),
    "/info.php": ("INFO-021", "HIGH", "PHP info page exposed",
                  re.compile(r"PHP Version|phpinfo", re.IGNORECASE)),
    # INFO-030: admin paths (status-based, no body match)
    "/wp-admin/": ("INFO-030", "MEDIUM", "WordPress admin path responds",
                   re.compile(r"WordPress|wp-login", re.IGNORECASE)),
    "/administrator/": ("INFO-030", "MEDIUM", "Joomla admin path responds",
                        re.compile(r"Joomla|Administration", re.IGNORECASE)),
    "/admin/": ("INFO-030", "MEDIUM", "Generic admin path responds",
                re.compile(r"admin|login", re.IGNORECASE)),
    # INFO-031: DB management
    "/phpmyadmin/": ("INFO-031", "MEDIUM", "phpMyAdmin exposed",
                     re.compile(r"phpMyAdmin", re.IGNORECASE)),
    "/adminer.php": ("INFO-031", "MEDIUM", "Adminer DB tool exposed",
                     re.compile(r"Adminer", re.IGNORECASE)),
    # INFO-040: API docs
    "/swagger-ui.html": ("INFO-040", "LOW", "Swagger UI exposed",
                         re.compile(r"swagger|api-docs", re.IGNORECASE)),
    "/swagger/": ("INFO-040", "LOW", "Swagger path exposed",
                  re.compile(r"swagger", re.IGNORECASE)),
    "/api-docs": ("INFO-040", "LOW", "API documentation exposed",
                  re.compile(r"swagger|openapi", re.IGNORECASE)),
    "/openapi.json": ("INFO-040", "LOW", "OpenAPI spec exposed",
                      re.compile(r'"openapi"|"swagger"', re.IGNORECASE)),
    "/v2/api-docs": ("INFO-040", "LOW", "Springfox API docs exposed",
                     re.compile(r'"swagger"', re.IGNORECASE)),
    # INFO-050: robots.txt (always informational; we look for sensitive paths inside)
    "/robots.txt": ("INFO-050", "INFO", "Robots.txt present (review Disallow paths)",
                    re.compile(r"^Disallow:|User-agent:", re.MULTILINE | re.IGNORECASE)),
}


# Source map detection — different shape (operator probes the actual
# .map URL, which depends on bundle naming). The map magic comment
# at top of bundle is `//# sourceMappingURL=...`. We detect both:
# (a) operator probes a specific .map URL and gets it; (b) operator
# greps for the source mapping comment in the JS bundle (out of
# scope for v1).
_JS_MAP_RE = re.compile(r"\.js\.map$", re.IGNORECASE)
_CSS_MAP_RE = re.compile(r"\.css\.map$", re.IGNORECASE)
_BACKUP_RE = re.compile(r"\.(bak|swp|old|orig|backup|tmp|~)$", re.IGNORECASE)


@dataclass(frozen=True)
class DisclosureProbe:
    """One operator-issued probe."""

    path: str  # e.g. "/.git/config"
    http_status: int
    body_fingerprint: str = ""  # first 200-500 chars of response body
    content_length: int = 0


@dataclass(frozen=True)
class DisclosureFinding:
    """One disclosure verdict."""

    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    path: str = ""


@dataclass(frozen=True)
class DisclosureAnalysis:
    """Aggregated analysis."""

    total_probes: int
    findings: tuple[DisclosureFinding, ...] = field(default_factory=tuple)


def default_probe_paths() -> list[str]:
    """The canonical probe path list. Operators can extend / restrict
    per engagement context."""
    return list(_PROBE_TABLE.keys())


def _classify_probe(probe: DisclosureProbe) -> DisclosureFinding | None:
    """Run the static checks against one probe. Returns None when
    no finding fires."""
    path = probe.path
    status = probe.http_status
    fingerprint = probe.body_fingerprint or ""

    # 4xx/5xx is generally a non-finding (path doesn't exist or
    # access is blocked correctly).
    if status >= 400 and path not in ("/robots.txt",):
        return None

    # JS/CSS source map: any 200 on a .js.map path is a finding.
    if _JS_MAP_RE.search(path) and status == 200:
        return DisclosureFinding(
            rule_id="INFO-010",
            severity="MEDIUM",
            title=f"JavaScript source map exposed ({path})",
            detail=(
                "Source maps reveal original (unminified) JavaScript "
                "source code + variable / function names. Speeds up "
                "reverse engineering + reveals internal patterns."
            ),
            remediation=(
                "Stop publishing .map files to production. Generate "
                "them locally for debugging, exclude from build artifact."
            ),
            path=path,
        )
    if _CSS_MAP_RE.search(path) and status == 200:
        return DisclosureFinding(
            rule_id="INFO-011",
            severity="LOW",
            title=f"CSS source map exposed ({path})",
            detail=(
                "CSS source maps reveal the original (pre-processor) "
                "CSS. Less impact than JS but still discloses internal "
                "file structure."
            ),
            remediation="Exclude .css.map from production builds.",
            path=path,
        )
    # Backup file by extension
    if _BACKUP_RE.search(path) and status == 200:
        return DisclosureFinding(
            rule_id="INFO-012",
            severity="HIGH",
            title=f"Backup file exposed ({path})",
            detail=(
                "Backup files (.bak / .swp / .old / .orig / ~) often "
                "contain the previous version of source code or "
                "configuration — sometimes with credentials still in "
                "them."
            ),
            remediation=(
                "Configure the web server to deny these extensions. "
                "nginx: `location ~ \\.(bak|swp|old|orig)$ { return 404; }`."
            ),
            path=path,
        )

    # Table-driven probes
    if path not in _PROBE_TABLE:
        return None
    rule_id, severity, title, body_re = _PROBE_TABLE[path]

    # Robots.txt is special: report when ANY Disallow line references
    # something sensitive (admin/api/auth/private)
    if rule_id == "INFO-050":
        if status != 200:
            return None
        sensitive = re.search(
            r"Disallow:\s*/(admin|api|backup|private|secret|auth|config)",
            fingerprint,
            re.IGNORECASE,
        )
        if sensitive:
            return DisclosureFinding(
                rule_id="INFO-050",
                severity="LOW",
                title="Robots.txt discloses sensitive paths",
                detail=(
                    f"robots.txt contains Disallow rules referencing "
                    f"sensitive paths (e.g. {sensitive.group(1)!r}). "
                    "Attackers read robots.txt FIRST to discover paths "
                    "the site wants to hide."
                ),
                remediation=(
                    "Don't enumerate sensitive paths in robots.txt. "
                    "Use proper access control instead — robots.txt is "
                    "public."
                ),
                path=path,
            )
        return None  # robots.txt exists but no sensitive disclosures

    # All other probes: 200 + body matches signature = finding.
    if status != 200:
        return None
    # If we have a body fingerprint, require it to match the
    # signature — avoids false positives from SPAs that 200 every
    # path with the same shell HTML.
    if fingerprint and not body_re.search(fingerprint):
        return None

    # If fingerprint is empty (caller did HEAD only), still flag —
    # but mention the caller should GET to confirm.
    detail_suffix = (
        ""
        if fingerprint and body_re.search(fingerprint)
        else " (probe used HEAD; recommend GET to confirm)"
    )

    return DisclosureFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=_default_detail(rule_id, path) + detail_suffix,
        remediation=_default_remediation(rule_id, path),
        path=path,
    )


def _default_detail(rule_id: str, path: str) -> str:
    if rule_id == "INFO-001":
        return (
            f"Version control metadata exposed at {path}. Attackers "
            "extract repository contents via `wget --mirror` against "
            "the .git/.svn/.hg directory + reconstruct source code."
        )
    if rule_id == "INFO-002":
        return (
            f"Environment file exposed at {path}. Typically contains "
            "API keys, database credentials, JWT signing secrets, "
            "third-party tokens."
        )
    if rule_id == "INFO-003":
        return (
            f"Database dump exposed at {path}. Direct download = full "
            "dataset including PII, credentials, internal state."
        )
    if rule_id == "INFO-020":
        return (
            f"Server status page at {path} reveals real-time request "
            "log + active connections + memory state. Information leak + "
            "potential timing-attack surface."
        )
    if rule_id == "INFO-021":
        return (
            f"phpinfo() page at {path} reveals PHP version, extensions, "
            "environment variables, server paths, OS details. "
            "Reconnaissance gold."
        )
    if rule_id == "INFO-030":
        return (
            f"Admin path {path} responds. Default admin URLs are the "
            "first place credential-stuffing bots try. Even if 'protected', "
            "auth bypass / brute-force surface."
        )
    if rule_id == "INFO-031":
        return (
            f"Database management UI exposed at {path}. Direct attack "
            "path against the DB if creds are weak / default."
        )
    if rule_id == "INFO-040":
        return (
            f"API documentation exposed at {path}. Reveals every "
            "endpoint, parameter, auth method — full attack surface "
            "blueprint."
        )
    return f"Resource exposed at {path}"


def _default_remediation(rule_id: str, path: str) -> str:
    if rule_id == "INFO-001":
        return (
            "Add web server rule to deny `.git/`, `.svn/`, `.hg/` "
            "directories. Move version control metadata OUT of the "
            "docroot."
        )
    if rule_id == "INFO-002":
        return (
            "Move .env files out of the document root. nginx: `location "
            "~ /\\.env { deny all; }`. Audit deploy scripts."
        )
    if rule_id == "INFO-020":
        return (
            "Disable Apache mod_status / mod_info in production OR "
            "restrict access by IP."
        )
    if rule_id == "INFO-021":
        return (
            "Remove phpinfo() / info.php / test.php files from production. "
            "These are debugging shims that shouldn't ship."
        )
    if rule_id == "INFO-030":
        return (
            "Rename admin paths to non-default URLs + enforce strong auth "
            "+ IP allow-listing. Add rate limiting to defeat enumeration."
        )
    if rule_id == "INFO-031":
        return (
            "Remove phpMyAdmin / Adminer from production. Use SSH "
            "tunneling for DB admin instead."
        )
    if rule_id == "INFO-040":
        return (
            "Gate API docs behind authentication, or remove from "
            "production entirely."
        )
    return "Remove from document root or restrict access by IP / auth."


def analyze_probes(probes: list[DisclosureProbe]) -> DisclosureAnalysis:
    """Run static classification over a list of probe results.

    Returns DisclosureAnalysis with findings sorted by severity
    (CRITICAL → INFO)."""
    findings: list[DisclosureFinding] = []
    for probe in probes:
        finding = _classify_probe(probe)
        if finding is not None:
            findings.append(finding)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id, f.path))
    return DisclosureAnalysis(total_probes=len(probes), findings=tuple(findings))
