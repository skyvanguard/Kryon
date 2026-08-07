"""F107 — DOM XSS Sink Detector.

Static JavaScript scanner that flags DOM-XSS sinks fed by user-
controlled sources, without executing any code. Operator hands a
JS bundle (or a small snippet) + the analyzer reports each
risky source→sink pattern.

Approach: regex-based, per-line. Two pass:

  (1) **Sinks** — DOM APIs that interpret strings as code/HTML:
      `eval`, `Function`, `setTimeout(STRING,...)`, `setInterval`,
      `document.write`, `innerHTML =`, `outerHTML =`, `insertAdjacentHTML`,
      `document.location =`, `location.href =`, `location.replace`,
      `location.assign`, `window.open`, `<a>.href =`, `script.src =`,
      `dangerouslySetInnerHTML`, `jQuery $.html()`, `$.append()`.
  (2) **Sources** — DOM APIs that yield user-controlled data:
      `location.hash`, `location.search`, `location.href`,
      `document.URL`, `document.documentURI`, `document.referrer`,
      `document.cookie`, `window.name`, `localStorage.getItem`,
      `sessionStorage.getItem`, `postMessage`'s `event.data`,
      `URLSearchParams.get`.

A finding fires when a sink reads from a source in the same line
OR within a small window (operator may pass `body` as one snippet
per function).

Stable rule IDs:

  DOM-001  eval / Function constructor with user input (CRITICAL)
  DOM-002  innerHTML / outerHTML / document.write with user input (HIGH)
  DOM-003  setTimeout / setInterval with string argument from user input (HIGH)
  DOM-004  location.href / location.assign / location.replace with user input (HIGH — open redirect + XSS via javascript:)
  DOM-005  jQuery .html() / .append() with user input (HIGH)
  DOM-006  insertAdjacentHTML with user input (HIGH)
  DOM-007  React dangerouslySetInnerHTML with user input (HIGH)
  DOM-008  script.src = user_input (CRITICAL)
  DOM-009  postMessage handler without origin check (HIGH)
  DOM-010  Suspicious use of eval/Function even without source (MEDIUM)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "JsSnippet",
    "DomXssFinding",
    "DomXssAnalysis",
    "analyze_dom_xss",
    "ALL_DOM_RULES",
]


ALL_DOM_RULES: frozenset[str] = frozenset({f"DOM-{n:03d}" for n in range(1, 11)})


# ---- Sources -----------------------------------------------------------
# Patterns that indicate user-controlled data.
_SOURCE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\blocation\.hash\b"),
    re.compile(r"\blocation\.search\b"),
    re.compile(r"\blocation\.href\b"),
    re.compile(r"\blocation\.pathname\b"),
    re.compile(r"\bdocument\.URL\b"),
    re.compile(r"\bdocument\.documentURI\b"),
    re.compile(r"\bdocument\.referrer\b"),
    re.compile(r"\bdocument\.cookie\b"),
    re.compile(r"\bwindow\.name\b"),
    re.compile(r"\blocalStorage\.getItem\s*\("),
    re.compile(r"\bsessionStorage\.getItem\s*\("),
    re.compile(r"new\s+URLSearchParams\s*\("),
    re.compile(r"\bevent\.data\b"),
    re.compile(r"\bmsg\.data\b"),
    re.compile(r"\bgetParameter\s*\("),  # framework wrappers
)


def _line_has_source(line: str) -> bool:
    return any(pat.search(line) for pat in _SOURCE_PATTERNS)


# ---- Sinks -------------------------------------------------------------
# (rule_id, severity, label, regex, requires_source)
_SINKS: tuple[tuple[str, str, str, re.Pattern, bool], ...] = (
    ("DOM-001", "CRITICAL", "eval()", re.compile(r"\beval\s*\("), True),
    ("DOM-001", "CRITICAL", "Function constructor", re.compile(r"\bnew\s+Function\s*\("), True),
    ("DOM-001", "CRITICAL", "Function() (no-new)", re.compile(r"(?<!\.)\bFunction\s*\("), True),
    ("DOM-002", "HIGH", "element.innerHTML =", re.compile(r"\.innerHTML\s*="), True),
    ("DOM-002", "HIGH", "element.outerHTML =", re.compile(r"\.outerHTML\s*="), True),
    ("DOM-002", "HIGH", "document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\("), True),
    ("DOM-003", "HIGH", "setTimeout with string", re.compile(r"\bsetTimeout\s*\(\s*['\"]"), False),
    ("DOM-003", "HIGH", "setInterval with string", re.compile(r"\bsetInterval\s*\(\s*['\"]"), False),
    ("DOM-004", "HIGH", "location.href = (assignment)", re.compile(r"\blocation\.href\s*="), True),
    ("DOM-004", "HIGH", "window.location = (assignment)", re.compile(r"\bwindow\.location\s*="), True),
    ("DOM-004", "HIGH", "location.assign", re.compile(r"\blocation\.assign\s*\("), True),
    ("DOM-004", "HIGH", "location.replace", re.compile(r"\blocation\.replace\s*\("), True),
    ("DOM-005", "HIGH", "jQuery $.html", re.compile(r"\$\([^)]*\)\.html\s*\("), True),
    ("DOM-005", "HIGH", "jQuery $.append", re.compile(r"\$\([^)]*\)\.append\s*\("), True),
    ("DOM-006", "HIGH", "insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\("), True),
    ("DOM-007", "HIGH", "React dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML\s*[:=]"), True),
    (
        "DOM-008",
        "CRITICAL",
        "script.src = user_input",
        re.compile(r"\.src\s*=\s*[^'\"]*(?:location\.|document\.|event\.data|window\.name|getItem)"),
        False,
    ),
)


@dataclass(frozen=True)
class JsSnippet:
    """A JS code snippet to scan."""

    file_path: str
    body: str  # the JS code
    line_offset: int = 0


@dataclass(frozen=True)
class DomXssFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    file_path: str = ""
    line: int = 0
    snippet: str = ""


@dataclass(frozen=True)
class DomXssAnalysis:
    total_snippets: int
    findings: tuple[DomXssFinding, ...] = field(default_factory=tuple)


def _has_source_nearby(lines: list[str], idx: int, window: int = 2) -> bool:
    """Check current line and `window` lines before/after for a source."""
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    return any(_line_has_source(lines[i]) for i in range(start, end))


def _truncate_snippet(line: str, max_len: int = 120) -> str:
    s = line.strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _classify_snippet(snippet: JsSnippet) -> list[DomXssFinding]:
    body = snippet.body or ""
    if not body:
        return []
    lines = body.split("\n")
    findings: list[DomXssFinding] = []
    findings_seen: set[tuple[str, int]] = set()
    has_eval = False

    for idx, line in enumerate(lines):
        # Skip pure comment lines
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue
        for rule_id, severity, label, pattern, requires_source in _SINKS:
            if not pattern.search(line):
                continue
            if requires_source and not _has_source_nearby(lines, idx):
                # Track for DOM-010 fallback
                if rule_id == "DOM-001":
                    has_eval = True
                continue
            key = (rule_id, idx + snippet.line_offset)
            if key in findings_seen:
                continue
            findings_seen.add(key)
            findings.append(
                DomXssFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=f"{label} sink fed by DOM source",
                    detail=(
                        f"Line uses {label} which writes/executes its argument "
                        "as HTML/JS, AND the same region reads from a "
                        "user-controlled DOM source (location.*, document.*, "
                        "event.data, storage, ...)."
                    ),
                    remediation=_remediation_for(rule_id),
                    file_path=snippet.file_path,
                    line=idx + 1 + snippet.line_offset,
                    snippet=_truncate_snippet(line),
                )
            )

    # DOM-010: eval/Function in code at all (defensive even without
    # confirmed source). Only fire if no DOM-001 already fired.
    if has_eval and not any(f.rule_id == "DOM-001" for f in findings):
        # Find first eval/Function line
        for idx, line in enumerate(lines):
            if re.search(r"\beval\s*\(|\bnew\s+Function\s*\(", line):
                findings.append(
                    DomXssFinding(
                        rule_id="DOM-010",
                        severity="MEDIUM",
                        title="eval() / Function() present (DOM-XSS surface)",
                        detail=(
                            "Code uses eval / Function() — even without a "
                            "confirmed DOM source on the same line, this is "
                            "a high-risk pattern. Manual review recommended."
                        ),
                        remediation="Eliminate eval. Use JSON.parse for data parsing.",
                        file_path=snippet.file_path,
                        line=idx + 1 + snippet.line_offset,
                        snippet=_truncate_snippet(line),
                    )
                )
                break

    # DOM-009: postMessage handler without origin check — heuristic.
    # We look for ANY `.origin` access in the snippet; the handler
    # variable might be named `e`, `event`, `msg`, etc.
    if re.search(r"window\.addEventListener\s*\(\s*['\"]message['\"]", body):
        if not re.search(r"\.origin\b", body):
            # find first line of the handler for reporting
            for idx, line in enumerate(lines):
                if re.search(r"addEventListener\s*\(\s*['\"]message['\"]", line):
                    findings.append(
                        DomXssFinding(
                            rule_id="DOM-009",
                            severity="HIGH",
                            title="postMessage handler without origin validation",
                            detail=(
                                "addEventListener('message', ...) but the "
                                "handler doesn't check event.origin. Any "
                                "iframe can send messages → DOM XSS / privilege "
                                "escalation."
                            ),
                            remediation=(
                                "Validate event.origin against a strict allow-"
                                "list at the top of the handler. Drop messages "
                                "from unexpected origins."
                            ),
                            file_path=snippet.file_path,
                            line=idx + 1 + snippet.line_offset,
                            snippet=_truncate_snippet(line),
                        )
                    )
                    break

    return findings


def _remediation_for(rule_id: str) -> str:
    if rule_id == "DOM-001":
        return (
            "Never call eval() / Function() on data derived from URL / "
            "storage / postMessage / etc. Parse JSON with JSON.parse + "
            "validate the schema."
        )
    if rule_id == "DOM-002":
        return (
            "Use textContent for inserting text. If HTML is required, "
            "sanitize via DOMPurify with a STRICT config before writing "
            "to innerHTML / outerHTML."
        )
    if rule_id == "DOM-003":
        return "Pass a FUNCTION to setTimeout / setInterval, never a string. Strings are evaluated as code."
    if rule_id == "DOM-004":
        return (
            "Validate the URL before assigning. Reject javascript: + data: + "
            "vbscript: schemes. Block off-site hosts where applicable."
        )
    if rule_id == "DOM-005":
        return (
            "Use .text() instead of .html() / .append() for user-controlled "
            "data. If HTML is required, sanitize with DOMPurify first."
        )
    if rule_id == "DOM-006":
        return (
            "insertAdjacentHTML is equivalent to innerHTML for XSS purposes. "
            "Use insertAdjacentText, or sanitize input first."
        )
    if rule_id == "DOM-007":
        return (
            "Avoid dangerouslySetInnerHTML. If unavoidable, sanitize the "
            "HTML server-side with a strict allow-list + render the "
            "sanitized result."
        )
    if rule_id == "DOM-008":
        return "Never let user input control a <script src>. Use a strict allow-list of script origins + CSP nonces."
    return "Validate / sanitize user input before reaching this sink."


def analyze_dom_xss(snippets: list[JsSnippet]) -> DomXssAnalysis:
    findings: list[DomXssFinding] = []
    for snippet in snippets:
        findings.extend(_classify_snippet(snippet))
    from kryon.util.severity import SEVERITY_RANK as severity_order

    findings.sort(
        key=lambda f: (
            severity_order.get(f.severity, 99),
            f.rule_id,
            f.file_path,
            f.line,
        )
    )
    return DomXssAnalysis(total_snippets=len(snippets), findings=tuple(findings))
