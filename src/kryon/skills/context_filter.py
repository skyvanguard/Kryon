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
    "_test.c",
    "_tests.c",
    "test_",
)

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
    r"if\s*\(\s*!\s*{var}\s*\)",
    r"if\s*\(\s*{var}\s*==\s*(NULL|nullptr|0)\s*\)",
    r"if\s*\(\s*{var}\s*!=\s*(NULL|nullptr|0)\s*\)",
    r"if\s*\(\s*!\s*{var}\s*\)\s*(return|goto|break|continue)",
    r"BUG_ON\s*\(\s*{var}\s*==\s*(NULL|nullptr|0)\s*\)",
    r"NULL_CHECK\s*\(\s*{var}\s*\)",
)

# Variable-name extraction from the line flagged. We look for the last
# identifier preceding ``->`` or ``[`` or ``*`` dereference.
_VAR_NEAR_DEREF_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z_0-9]*)\s*(?:->|\[|\.\s*[A-Za-z_])"
)


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
        lower = file_path.lower().replace("\\", "/")
        if any(frag in lower for frag in _TEST_PATH_FRAGMENTS):
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
        var = _extract_dereffed_var(flagged_line)
        if var:
            preceding = "\n".join(lines[lo:line - 1])
            if _has_null_check(preceding, var):
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


def _has_null_check(window_text: str, var: str) -> bool:
    escaped = re.escape(var)
    for template in _NULL_CHECK_TEMPLATES:
        pattern = template.replace("{var}", escaped)
        if re.search(pattern, window_text):
            return True
    return False


__all__ = ["ContextFilter", "ContextVerdict"]
