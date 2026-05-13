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


ALL_VJS_RULES: frozenset[str] = frozenset(f"VJS-{n:03d}" for n in range(1, 51))


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
    # F102 v2 — expanded catalog
    ("vue", re.compile(r"vue[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("react", re.compile(r"react[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("react-dom", re.compile(r"react-dom[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("angular2", re.compile(r"@angular/core[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("ember", re.compile(r"ember[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("backbone", re.compile(r"backbone[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("knockout", re.compile(r"knockout[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("prototype", re.compile(r"prototype[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("mootools", re.compile(r"mootools[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("marked", re.compile(r"marked[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("ejs", re.compile(r"ejs[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("mustache", re.compile(r"mustache[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("pug", re.compile(r"pug[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("validator", re.compile(r"validator[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("jsonwebtoken", re.compile(r"jsonwebtoken[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("ws", re.compile(r"^(?:.*/)?ws[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js$", re.IGNORECASE)),
    ("express", re.compile(r"express[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("socket.io", re.compile(r"socket\.io[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("serialize-javascript", re.compile(r"serialize-javascript[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("qs", re.compile(r"(?:^|/)qs[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("semver", re.compile(r"semver[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("ajv", re.compile(r"ajv[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("uglify-js", re.compile(r"uglify-?js[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("jsrsasign", re.compile(r"jsrsasign[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("crypto-js", re.compile(r"crypto-js[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("jszip", re.compile(r"jszip[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("papaparse", re.compile(r"papaparse[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("dayjs", re.compile(r"dayjs[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("ckeditor", re.compile(r"ckeditor[/-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("tinymce", re.compile(r"tinymce[/-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("chart.js", re.compile(r"chart(?:\.js)?[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("d3", re.compile(r"d3(?:\.v\d+)?[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("highcharts", re.compile(r"highcharts[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("video.js", re.compile(r"video(?:\.js)?[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("plyr", re.compile(r"plyr[/-](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.js", re.IGNORECASE)),
    ("swiper", re.compile(r"swiper[/-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
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
    # F102 v2 — expanded catalog
    ("VJS-017", "vue", (2, 7, 0), "MEDIUM", "GHSA-cf4h-3jhx-xvhq",
     "Vue 2.x pre-2.7 has known XSS vectors in v-html with attacker-controlled markup",
     "Upgrade to Vue 2.7+ or migrate to Vue 3.x. Avoid v-html on user input."),
    ("VJS-018", "react", (16, 4, 2), "MEDIUM", "CVE-2018-6341",
     "React pre-16.4.2 has XSS via render() on user-controlled href= attribute (javascript: scheme)",
     "Upgrade React to 16.4.2 or later."),
    ("VJS-019", "react-dom", (16, 4, 2), "MEDIUM", "CVE-2018-6341",
     "ReactDOM pre-16.4.2 same XSS as React (javascript: scheme not blocked)",
     "Upgrade react-dom to 16.4.2 or later."),
    ("VJS-020", "angular2", (11, 0, 5), "MEDIUM", "CVE-2020-7676",
     "Angular 2-10 had XSS in [innerHTML] sanitizer bypass",
     "Upgrade Angular to 11.0.5 or later."),
    ("VJS-021", "ember", (3, 24, 0), "MEDIUM", "CVE-2021-32820",
     "Ember pre-3.24 had XSS in {{html-safe}} helper with mixed encoding",
     "Upgrade Ember to 3.24.0 or later (LTS)."),
    ("VJS-022", "backbone", (1, 4, 1), "LOW", "GHSA-8jhw-289h-jh2g",
     "Backbone pre-1.4.1 had a regex DoS in Backbone.View",
     "Upgrade Backbone to 1.4.1 or later."),
    ("VJS-023", "knockout", (3, 5, 1), "MEDIUM", "CVE-2019-14862",
     "Knockout pre-3.5.1 had XSS in data-bind attribute parsing",
     "Upgrade Knockout to 3.5.1 or later."),
    ("VJS-024", "prototype", (1, 7, 4), "HIGH", "CVE-2007-2382",
     "Prototype.js pre-1.7.4 had multiple XSS + abandoned upstream",
     "Migrate away from Prototype.js (project effectively abandoned)."),
    ("VJS-025", "mootools", (1, 6, 0), "HIGH", "Multiple",
     "MooTools is unmaintained as of ~2018; multiple known XSS + project EOL",
     "Migrate to a maintained library."),
    ("VJS-026", "marked", (4, 0, 10), "HIGH", "CVE-2022-21680",
     "marked pre-4.0.10 had ReDoS in inline tokenizer (parsing untrusted markdown)",
     "Upgrade marked to 4.0.10 or later."),
    ("VJS-027", "marked", (0, 6, 2), "HIGH", "CVE-2017-16114",
     "marked pre-0.6.2 had XSS via crafted markdown links",
     "Upgrade marked to 0.6.2+ (better: 4.0.10+)."),
    ("VJS-028", "ejs", (3, 1, 7), "CRITICAL", "CVE-2022-29078",
     "EJS pre-3.1.7 had RCE via options.outputFunctionName prototype pollution",
     "Upgrade EJS to 3.1.7 or later. Never render user-controlled templates."),
    ("VJS-029", "mustache", (2, 2, 1), "MEDIUM", "CVE-2015-8862",
     "Mustache.js pre-2.2.1 had XSS via section name lookup",
     "Upgrade Mustache.js to 2.2.1 or later."),
    ("VJS-030", "pug", (3, 0, 1), "CRITICAL", "CVE-2021-21353",
     "Pug pre-3.0.1 had RCE in compileClient via crafted template",
     "Upgrade Pug to 3.0.1 or later."),
    ("VJS-031", "validator", (13, 7, 0), "MEDIUM", "CVE-2021-3765",
     "validator.js pre-13.7.0 had ReDoS in isEmail / isURL with crafted input",
     "Upgrade validator.js to 13.7.0 or later."),
    ("VJS-032", "jsonwebtoken", (9, 0, 0), "CRITICAL", "CVE-2022-23541",
     "jsonwebtoken pre-9.0.0 had auth-bypass via algorithm confusion (HS256 vs RS256)",
     "Upgrade jsonwebtoken to 9.0.0 or later. Always specify the expected algorithm in verify()."),
    ("VJS-033", "ws", (7, 5, 9), "HIGH", "CVE-2024-37890",
     "ws pre-7.5.10/8.17.1 had DoS via crafted Sec-WebSocket-Protocol headers",
     "Upgrade ws to 7.5.10 / 8.17.1 or later."),
    ("VJS-034", "express", (4, 17, 3), "MEDIUM", "CVE-2022-24999",
     "Express pre-4.17.3 with qs vulnerable to ReDoS via deep nested query strings",
     "Upgrade Express to 4.17.3+ (which pins qs ≥ 6.7.3)."),
    ("VJS-035", "socket.io", (4, 6, 2), "HIGH", "CVE-2024-38355",
     "Socket.IO pre-4.6.2 had DoS via crafted packets crashing the server",
     "Upgrade socket.io to 4.6.2 or later."),
    ("VJS-036", "serialize-javascript", (6, 0, 2), "HIGH", "CVE-2024-11831",
     "serialize-javascript pre-6.0.2 had XSS via crafted regex / Date arguments",
     "Upgrade serialize-javascript to 6.0.2 or later."),
    ("VJS-037", "qs", (6, 11, 0), "HIGH", "CVE-2022-24999",
     "qs pre-6.11.0 had ReDoS + prototype pollution risks",
     "Upgrade qs to 6.11.0 or later."),
    ("VJS-038", "semver", (7, 5, 2), "MEDIUM", "CVE-2022-25883",
     "semver pre-7.5.2 had ReDoS in new Range() with crafted input",
     "Upgrade semver to 7.5.2 or later."),
    ("VJS-039", "ajv", (6, 12, 3), "MEDIUM", "CVE-2020-15366",
     "ajv pre-6.12.3 had prototype pollution via crafted schema",
     "Upgrade ajv to 6.12.3+ or 7.x+."),
    ("VJS-040", "crypto-js", (4, 2, 0), "HIGH", "CVE-2023-46233",
     "crypto-js pre-4.2.0 had insecure PBKDF2 default iterations (1!)",
     "Upgrade crypto-js to 4.2.0+. Explicitly set high iteration count."),
    ("VJS-041", "jszip", (3, 8, 0), "MEDIUM", "CVE-2022-48285",
     "jszip pre-3.8.0 had path-traversal in loadAsync (zip-slip)",
     "Upgrade jszip to 3.8.0 or later. Validate output paths."),
    ("VJS-042", "papaparse", (5, 2, 0), "MEDIUM", "CVE-2020-26307",
     "Papa Parse pre-5.2.0 had ReDoS in CSV parsing",
     "Upgrade papaparse to 5.2.0 or later."),
    ("VJS-043", "dayjs", (1, 11, 4), "MEDIUM", "CVE-2024-7254",
     "dayjs pre-1.11.4 had ReDoS in parsing crafted date strings",
     "Upgrade dayjs to 1.11.4 or later."),
    ("VJS-044", "ckeditor", (4, 24, 0), "HIGH", "CVE-2024-24815",
     "CKEditor 4 pre-4.24.0 had XSS in clipboard paste filter",
     "Upgrade CKEditor 4 to 4.24.0+, or migrate to CKEditor 5."),
    ("VJS-045", "tinymce", (5, 10, 0), "HIGH", "CVE-2021-44878",
     "TinyMCE pre-5.10.0 had stored XSS in HTML conversion",
     "Upgrade TinyMCE to 5.10.0 or later (recommend 6.x)."),
    ("VJS-046", "chart.js", (2, 9, 4), "MEDIUM", "CVE-2020-7746",
     "Chart.js pre-2.9.4 had XSS in tooltip rendering of user-controlled labels",
     "Upgrade Chart.js to 2.9.4+ (recommend 4.x)."),
    ("VJS-047", "d3", (3, 5, 17), "MEDIUM", "GHSA-36jr-mh4h-2g58",
     "D3.js pre-3.5.17 (and old v4 lines) had XSS in d3.html templates",
     "Upgrade D3 to 7.x. Avoid d3.html with user input."),
    ("VJS-048", "highcharts", (9, 0, 0), "MEDIUM", "CVE-2022-23439",
     "Highcharts pre-9.0 had XSS in label rendering of crafted strings",
     "Upgrade Highcharts to 9.0+."),
    ("VJS-049", "video.js", (7, 14, 3), "MEDIUM", "CVE-2020-23633",
     "video.js pre-7.14.3 had XSS in track-text rendering",
     "Upgrade video.js to 7.14.3 or later."),
    ("VJS-050", "swiper", (8, 4, 5), "LOW", "GHSA-mw5p-w7gx-jxx5",
     "Swiper pre-8.4.5 had prototype pollution risk via params merge",
     "Upgrade Swiper to 8.4.5 or later."),
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
