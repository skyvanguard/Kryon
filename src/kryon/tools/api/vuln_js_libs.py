"""F102 — Vulnerable JavaScript Library Detector.

Static analyzer that takes a list of `(script_src, content_snippet)`
tuples + identifies known-vulnerable JS library versions.

Approach: like Retire.js + Snyk JS scanners, but pure-Python and
offline. Operator scrapes `<script src=...>` URLs + small body
fingerprints from the page; analyzer extracts the version and
matches against a curated CVE table.

Stable rule IDs (one per CVE family):

  VJS-001  jQuery < 3.5.0 (CVE-2020-11023, XSS via htmlPrefilter)
  VJS-002  jQuery < 3.4.0 (CVE-2019-11358, prototype pollution)
  VJS-003  AngularJS < 1.8.0 (multiple XSS in expressions)
  VJS-004  Bootstrap < 4.3.1 (CVE-2019-8331, XSS in tooltips/popovers)
  VJS-005  Bootstrap < 3.4.0 (CVE-2018-14040..14042, XSS)
  VJS-006  Lodash < 4.17.21 (CVE-2021-23337, command injection in template)
  VJS-007  Lodash < 4.17.12 (CVE-2019-10744, prototype pollution)
  VJS-008  Moment.js < 2.29.4 (CVE-2022-31129, ReDoS)
  VJS-009  Underscore < 1.12.1 (CVE-2021-23358, command injection in template)
  VJS-010  Axios < 0.21.2 (CVE-2021-3749, ReDoS)
  VJS-011  Axios < 0.21.1 (CVE-2020-28168, SSRF via redirects)
  VJS-012  React-Router < 5.2.1 / 6.0.0 (open redirect via state)
  VJS-013  DOMPurify < 2.0.17 (mXSS bypasses)
  VJS-014  Handlebars < 4.7.7 (CVE-2021-23369, prototype pollution)
  VJS-015  jQuery UI < 1.13.0 (CVE-2021-41182..41184, XSS)
  VJS-016  jQuery < 3.0.0 (CVE-2015-9251, XSS via cross-domain ajax)

Pure static. Same finding shape as F97/F98/F100/F101.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "ScriptObservation",
    "JSLibFinding",
    "JSLibAnalysis",
    "analyze_scripts",
    "ALL_VJS_RULES",
]


ALL_VJS_RULES: frozenset[str] = frozenset(f"VJS-{n:03d}" for n in range(1, 17))


# Version-comparison helper. Treats versions as dotted ints; pads with
# zeros so 3.4 < 3.4.1. Pre-release suffixes are stripped (3.0.0-rc1
# becomes 3.0.0).
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def _parse_version(text: str) -> tuple[int, ...] | None:
    m = _VERSION_RE.match(text.strip())
    if not m:
        return None
    parts = m.group(1).split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Tuple less-than with zero-padding so (3,4) < (3,4,1)."""
    length = max(len(a), len(b))
    aa = a + (0,) * (length - len(a))
    bb = b + (0,) * (length - len(b))
    return aa < bb


# Filename + URL patterns we extract the version from. The map values
# are (library_label, version_regex_groups).
_LIB_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("jquery", re.compile(r"jquery[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("jquery-ui", re.compile(r"jquery[-.]ui[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("angular", re.compile(r"angular(?:js)?[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("moment", re.compile(r"moment[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("underscore", re.compile(r"underscore[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("axios", re.compile(r"axios[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("react-router", re.compile(r"react-router[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("dompurify", re.compile(r"dompurify[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("handlebars", re.compile(r"handlebars[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
)

# Body fingerprint patterns — when URL has no version (e.g.
# `/js/jquery.min.js` without a version segment) we look for the
# version banner that most libraries embed in their source.
_BODY_VERSION_PATTERNS: dict[str, re.Pattern] = {
    "jquery": re.compile(r"jQuery (?:JavaScript Library )?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "jquery-ui": re.compile(r"jQuery UI(?: -)? (?:v)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "angular": re.compile(r"AngularJS v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "bootstrap": re.compile(r"Bootstrap v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "lodash": re.compile(r"lodash[@/](\d+\.\d+(?:\.\d+)?)|VERSION\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", re.IGNORECASE),
    "moment": re.compile(r"moment\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", re.IGNORECASE),
}

# Rule table — (rule_id, library, max_unsafe_version_exclusive, severity, CVE, description, remediation).
# "max_unsafe_version_exclusive" means "fixed in this version", i.e.
# the lib is vulnerable when version < this.
_RULE_TABLE: tuple[tuple[str, str, tuple[int, ...], str, str, str, str], ...] = (
    ("VJS-001", "jquery", (3, 5, 0), "MEDIUM", "CVE-2020-11023",
     "XSS in jQuery.htmlPrefilter (HTML with options can execute scripts)",
     "Upgrade jQuery to 3.5.0 or later."),
    ("VJS-002", "jquery", (3, 4, 0), "MEDIUM", "CVE-2019-11358",
     "Prototype pollution in jQuery.extend(true, ...)",
     "Upgrade jQuery to 3.4.0 or later."),
    ("VJS-003", "angular", (1, 8, 0), "HIGH", "CVE-2019-14863",
     "AngularJS pre-1.8.0 has multiple XSS bypasses in expression parsing",
     "Migrate to a maintained framework (AngularJS reached EOL 2022). At minimum upgrade to 1.8.x."),
    ("VJS-004", "bootstrap", (4, 3, 1), "MEDIUM", "CVE-2019-8331",
     "XSS in Bootstrap tooltip/popover via data-template attribute",
     "Upgrade Bootstrap to 4.3.1 or later."),
    ("VJS-005", "bootstrap", (3, 4, 0), "MEDIUM", "CVE-2018-14041",
     "XSS in Bootstrap 3 affix/collapse/scrollspy data attributes",
     "Upgrade Bootstrap to 3.4.0 or later (or 4.x)."),
    ("VJS-006", "lodash", (4, 17, 21), "HIGH", "CVE-2021-23337",
     "Command injection in lodash _.template via prototype pollution",
     "Upgrade lodash to 4.17.21 or later."),
    ("VJS-007", "lodash", (4, 17, 12), "HIGH", "CVE-2019-10744",
     "Prototype pollution in lodash defaultsDeep",
     "Upgrade lodash to 4.17.12 or later."),
    ("VJS-008", "moment", (2, 29, 4), "MEDIUM", "CVE-2022-31129",
     "Catastrophic backtracking (ReDoS) in moment().parse",
     "Upgrade moment to 2.29.4 or later. Better: migrate to date-fns/luxon."),
    ("VJS-009", "underscore", (1, 12, 1), "HIGH", "CVE-2021-23358",
     "Command injection in underscore _.template",
     "Upgrade underscore to 1.12.1 or later."),
    ("VJS-010", "axios", (0, 21, 2), "MEDIUM", "CVE-2021-3749",
     "ReDoS in axios trim() called against user-controlled header",
     "Upgrade axios to 0.21.2 or later."),
    ("VJS-011", "axios", (0, 21, 1), "HIGH", "CVE-2020-28168",
     "SSRF in axios when following redirects to internal hosts",
     "Upgrade axios to 0.21.1 or later."),
    ("VJS-012", "react-router", (5, 2, 1), "LOW", "GHSA-rqcj-pfh5-pmjw",
     "Open redirect risk in react-router state handling",
     "Upgrade react-router to 5.2.1+ or 6.x."),
    ("VJS-013", "dompurify", (2, 0, 17), "HIGH", "CVE-2020-26870",
     "DOMPurify pre-2.0.17 had mXSS bypass via mutation XSS payloads",
     "Upgrade DOMPurify to 2.0.17 or later (recommend latest 3.x)."),
    ("VJS-014", "handlebars", (4, 7, 7), "HIGH", "CVE-2021-23369",
     "Prototype pollution in Handlebars compiler enabling RCE in templates",
     "Upgrade Handlebars to 4.7.7 or later."),
    ("VJS-015", "jquery-ui", (1, 13, 0), "MEDIUM", "CVE-2021-41182",
     "XSS in jQuery UI .position(), .draggable(), datepicker pre-1.13.0",
     "Upgrade jQuery UI to 1.13.0 or later."),
    ("VJS-016", "jquery", (3, 0, 0), "MEDIUM", "CVE-2015-9251",
     "XSS via cross-domain ajax (jsonp) on jQuery pre-3.0",
     "Upgrade jQuery to 3.x. Avoid jsonp; use CORS instead."),
)


@dataclass(frozen=True)
class ScriptObservation:
    """One <script src> + optional body fingerprint."""

    src: str  # e.g. "/static/jquery-1.8.3.min.js"
    body_fingerprint: str = ""  # first ~500 chars of script body


@dataclass(frozen=True)
class JSLibFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    library: str = ""
    detected_version: str = ""
    cve: str = ""
    script_src: str = ""


@dataclass(frozen=True)
class JSLibAnalysis:
    total_scripts: int
    findings: tuple[JSLibFinding, ...] = field(default_factory=tuple)


def _identify_library(obs: ScriptObservation) -> tuple[str, tuple[int, ...]] | None:
    """Return (library_name, version_tuple) or None."""
    src = obs.src
    for lib, pattern in _LIB_PATTERNS:
        m = pattern.search(src)
        if m:
            version = _parse_version(m.group(1))
            if version is not None:
                return (lib, version)
    # Fall back to body inspection.
    body = obs.body_fingerprint
    if not body:
        return None
    for lib, pattern in _BODY_VERSION_PATTERNS.items():
        m = pattern.search(body)
        if m:
            # Try group 1, fall back to group 2 if the regex has alternates
            raw = next((g for g in m.groups() if g), None)
            if raw is None:
                continue
            version = _parse_version(raw)
            if version is not None:
                return (lib, version)
    return None


def _classify_observation(obs: ScriptObservation) -> list[JSLibFinding]:
    """Return all rule violations for a single observation."""
    identified = _identify_library(obs)
    if identified is None:
        return []
    lib, version = identified
    findings: list[JSLibFinding] = []
    for rule_id, rule_lib, fixed_in, severity, cve, detail, remediation in _RULE_TABLE:
        if rule_lib != lib:
            continue
        if _lt(version, fixed_in):
            findings.append(
                JSLibFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=f"{lib} {'.'.join(str(p) for p in version)} is vulnerable ({cve})",
                    detail=detail,
                    remediation=remediation,
                    library=lib,
                    detected_version=".".join(str(p) for p in version),
                    cve=cve,
                    script_src=obs.src,
                )
            )
    return findings


def analyze_scripts(observations: list[ScriptObservation]) -> JSLibAnalysis:
    """Run static analysis over a list of script observations.

    Sorts findings by severity (HIGH first), then library."""
    findings: list[JSLibFinding] = []
    for obs in observations:
        findings.extend(_classify_observation(obs))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(
        key=lambda f: (severity_order.get(f.severity, 99), f.library, f.rule_id)
    )
    return JSLibAnalysis(total_scripts=len(observations), findings=tuple(findings))
