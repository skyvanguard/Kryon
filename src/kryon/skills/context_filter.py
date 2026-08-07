"""F75 Fase 2 — Context-window based FP suppression.

Given a finding with ``file_path`` and ``line_range``, inspect the ±N
line window around it. If the surrounding source clearly shows the
pattern is safe (explicit null check, safety comment, dead code, test
path), downgrade the finding or stamp a suppression flag.

Design goals:
- Pure regex + filesystem reads, **no LLM** — fast enough to run on every
  finding without caching.
- Never deletes findings: mutates the finding dict in-place by setting
  ``_context_downgrade`` and optionally reducing ``severity`` / adding
  a ``triage_verdict`` hint. The hybrid runner / analyst decides what
  to do with annotated findings.
- Idempotent: running apply() twice on the same finding is a no-op.

The heuristics are intentionally conservative — they should only catch
obvious FPs (sentinel NULL check, clearly marked safe code, files under
tests/). Anything ambiguous stays HIGH.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# Paths that are typically non-production: harmless to downgrade findings.
_TEST_PATH_FRAGMENTS: tuple[str, ...] = (
    "/tests/",
    "/test/",
    "/testing/",
    "/examples/",
    "/sample/",
    "/samples/",
    "/demo/",
    "/demos/",
    "/deprecated/",
    "/legacy/",
    "/third_party/",
    "/vendor/",
)

# Directory segments that mark a non-production path — matched SEGMENT-wise (a
# whole path component equals one of these), so a 'test' segment anywhere
# (including the first) matches while 'latest_release' / 'attestation' (segments
# that merely CONTAIN 'test') do not.
_TEST_DIR_SEGMENTS: frozenset[str] = frozenset(
    {
        "tests",
        "test",
        "testing",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "deprecated",
        "legacy",
        "third_party",
        "vendor",
    }
)
# Basename markers — matched against the FILE NAME only, never as a raw substring
# ('test_' as a substring false-matched 'latest_release/parser.c').
_TEST_FILE_SUFFIXES: tuple[str, ...] = ("_test.c", "_tests.c", "_test.cpp", "_test.cc", "_test.py", "_test.go")
_TEST_FILE_PREFIXES: tuple[str, ...] = ("test_", "test-")


def _is_test_path(file_path: str) -> bool:
    """True if the path is a test / non-production file. Directory markers match
    per path-segment (not raw substring), and file markers match the basename
    only — so production files like 'latest_release/parser.c' or 'contest_manager.c'
    are NOT misclassified (which silently downgraded their findings)."""
    lower = (file_path or "").lower().replace("\\", "/")
    segments = lower.split("/")
    if any(seg in _TEST_DIR_SEGMENTS for seg in segments):
        return True
    basename = segments[-1]
    return basename.endswith(_TEST_FILE_SUFFIXES) or basename.startswith(_TEST_FILE_PREFIXES)


# Safe-markers the analyst or prior reviewer may have left.
_SAFE_COMMENT_RE = re.compile(
    r"//\s*(SAFE|CHECKED|REVIEWED|OK|NOFIX|COVERITY-?NOFIX|NOSONAR|"
    r"CodeQL-OK|suppress|false\s*positive)",
    re.IGNORECASE,
)

# Dead-code markers: `#if 0` … `#endif` / `#if defined(NEVER)` / `#if false`.
_DEAD_CODE_RE = re.compile(
    r"#\s*if\s+(0|false|defined\s*\(\s*(NEVER|UNUSED|DISABLED)\s*\))",
    re.IGNORECASE,
)

# Assert / NULL-check patterns that null-deref findings shouldn't flag.
# Matches `assert(ptr != NULL)`, `if (!ptr)`, `if (ptr == NULL) return`, etc.
_NULL_CHECK_TEMPLATES: tuple[str, ...] = (
    r"assert\s*\(\s*!?\s*{var}\s*(!=|==)?\s*(NULL|nullptr|0)?\s*\)",
    # A NEGATIVE check only guards the later deref if it ESCAPES control flow.
    # `if (!ptr) { log(); } ptr->x;` is a fall-through, NOT a guard — the bare
    # `if (!ptr)` / `if (ptr == NULL)` templates suppressed those unsafe derefs.
    # Require return/goto/break/continue immediately after (a body with other
    # statements before the escape stays flagged — precision over recall for a
    # security suppressor).
    r"if\s*\(\s*!\s*{var}\s*\)\s*\{?\s*(return|goto|break|continue)",
    r"if\s*\(\s*{var}\s*==\s*(NULL|nullptr|0)\s*\)\s*\{?\s*(return|goto|break|continue)",
    # A POSITIVE check guards its own body — valid without an escape.
    r"if\s*\(\s*{var}\s*!=\s*(NULL|nullptr|0)\s*\)",
    r"BUG_ON\s*\(\s*{var}\s*==\s*(NULL|nullptr|0)\s*\)",
    r"NULL_CHECK\s*\(\s*{var}\s*\)",
)

# Variable-name extraction from the line flagged. We look for the last
# identifier preceding ``->`` or ``[`` or ``*`` dereference.
_VAR_NEAR_DEREF_RE = re.compile(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*(?:->|\[|\.\s*[A-Za-z_])")


@dataclass(frozen=True)
class ContextVerdict:
    """Why we chose to downgrade (or not). Stamped onto finding."""

    downgrade: bool
    reason: str  # "null_check" | "safe_comment" | "dead_code" | "test_path" | ""
    window_lines: int  # how many lines we inspected


class ContextFilter:
    """Downgrade findings whose surrounding context is obviously safe."""

    def __init__(self, window: int = 3) -> None:
        self.window = window

    # Severity levels considered "actionable high" — downgrade candidates.
    # Kryon hunters emit these as their strong signal:
    #   - semgrep rules marked `severity: ERROR`
    #   - heuristic patterns with `confidence: high` (emit HIGH/CRITICAL)
    #   - validator-asserted CRITICAL
    _HIGH_BUCKET = {"HIGH", "CRITICAL", "ERROR"}

    def apply(self, findings: list[dict]) -> list[dict]:
        """Mutate findings in-place, return same list. Each finding
        touched gets ``_context_downgrade: ContextVerdict`` set."""
        for f in findings:
            if "_context_downgrade" in f:
                continue  # idempotent: already run
            verdict = self._evaluate(f)
            f["_context_downgrade"] = {
                "downgrade": verdict.downgrade,
                "reason": verdict.reason,
                "window_lines": verdict.window_lines,
            }
            if verdict.downgrade:
                sev_raw = str(f.get("severity", "")).upper()
                if sev_raw in self._HIGH_BUCKET:
                    f["severity_original"] = f.get("severity", "")
                    f["severity"] = "MEDIUM"
                    f["_severity_source"] = f"F75-ctx:{verdict.reason}"
                # Set a mild triage hint so downstream consumers can
                # see the context filter's view without clobbering any
                # existing LLM triage verdict.
                f.setdefault("context_verdict", verdict.reason)
        return findings

    # ------------------------------------------------------------------

    def _evaluate(self, finding: dict) -> ContextVerdict:
        file_path = finding.get("file_path") or finding.get("file") or ""
        if not file_path:
            return ContextVerdict(False, "", 0)

        # Cheap check first — test / deprecated paths.
        if _is_test_path(file_path):
            return ContextVerdict(True, "test_path", 0)

        line = _extract_line(finding)
        if line <= 0:
            return ContextVerdict(False, "", 0)

        lines = _read_source(file_path)
        if not lines or line > len(lines):
            return ContextVerdict(False, "", 0)

        lo = max(0, line - 1 - self.window)
        hi = min(len(lines), line + self.window)
        window_text = "\n".join(lines[lo:hi])

        if _SAFE_COMMENT_RE.search(window_text):
            return ContextVerdict(True, "safe_comment", hi - lo)

        if _DEAD_CODE_RE.search(window_text):
            return ContextVerdict(True, "dead_code", hi - lo)

        # Null-check: extract candidate var from the flagged line itself
        # and look for a prior check that guards the deref.
        flagged_line = lines[line - 1] if line - 1 < len(lines) else ""
        deref_vars = _extract_dereffed_vars(flagged_line)
        if deref_vars:
            preceding = "\n".join(lines[lo : line - 1])
            # Suppress only if EVERY dereferenced var on the flagged line is guarded.
            # If any deref is unchecked, the finding may be about that one — keep it.
            if all(_has_null_check(preceding, v) for v in deref_vars):
                return ContextVerdict(True, "null_check", line - 1 - lo)

        return ContextVerdict(False, "", hi - lo)


# ----------------------------------------------------------------------
# Helpers


def _extract_line(finding: dict) -> int:
    raw = finding.get("line_range") or finding.get("line") or ""
    raw = str(raw).lstrip("~")
    if not raw:
        return 0
    token = raw.split("-", 1)[0].strip()
    try:
        return int(token)
    except ValueError:
        return 0


def _read_source(file_path: str) -> list[str]:
    try:
        return Path(file_path).read_text(errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return []


def _extract_dereffed_var(line: str) -> str:
    """Pick the most likely dereferenced variable on the flagged line.
    Returns empty if we can't confidently name a single target."""
    matches = _VAR_NEAR_DEREF_RE.findall(line)
    if not matches:
        return ""
    # Bias toward the first dereffed identifier; that is usually the
    # subject of the deref that the scanner flagged.
    return matches[0]


def _extract_dereffed_vars(line: str) -> list[str]:
    """All distinct dereferenced identifiers on the flagged line, in order.

    Suppression must consider EVERY deref: a line like ``x->f = other->g;`` where
    only ``x`` is null-checked must not suppress a finding about ``other``. The
    single-var version biased to ``matches[0]`` and could attribute a check to the
    wrong variable.
    """
    seen: set[str] = set()
    out: list[str] = []
    for m in _VAR_NEAR_DEREF_RE.findall(line):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def _has_null_check(window_text: str, var: str) -> bool:
    escaped = re.escape(var)
    for template in _NULL_CHECK_TEMPLATES:
        pattern = template.replace("{var}", escaped)
        if re.search(pattern, window_text):
            return True
    return False


__all__ = ["ContextFilter", "ContextVerdict"]
