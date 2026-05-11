"""Base class for the source-code CWE experts.

Every concrete expert:
  - Declares its CWE family (`cwe_family` tuple).
  - Inherits :meth:`investigate` which walks the repo's source files,
    runs the regex patterns from the YAML library filtered to the
    family, and emits :class:`Finding` records.
  - Consumes exactly 1 budget unit per file scanned.

Concrete experts can override :meth:`investigate` wholesale when a more
specialised workflow is warranted (e.g. NumericExpert adds a guard-clause
filter before emitting). The base implementation is a reasonable default
for all pattern-driven CWEs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from kryon.skills.patterns import iter_all_patterns
from kryon.skills.validator_agent import Finding

# File extensions we consider source code worth scanning. The Juliet test
# suite and most C/C++ OSS use .c / .cpp / .h / .hpp; Python / JS are
# handled by separate experts in the web pipeline.
_SOURCE_SUFFIXES: tuple[str, ...] = (
    ".c", ".cc", ".cpp", ".cxx",
    ".h", ".hh", ".hpp", ".hxx",
    ".m", ".mm",  # Objective-C
)


@dataclass
class SourceExpertResult:
    """What one expert returns after scanning a repo."""

    expert_id: str
    cwe_family: list[str]
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    patterns_applied: int = 0
    budget_used: int = 0
    budget_available: int = 0
    notes: list[str] = field(default_factory=list)


class SourceExpert:
    """Abstract base for source-code experts.

    Subclasses declare:
      - :attr:`expert_id`        — short label
      - :attr:`cwe_family`       — tuple of CWE strings, e.g. ("CWE-787",)
      - :attr:`max_budget`       — default per-expert file cap
      - :attr:`confidence_floor` — regex confidence level below which
                                    we skip emitting. "medium" by default.
    """

    expert_id: str = "unknown"
    cwe_family: tuple[str, ...] = ()
    max_budget: int = 40
    confidence_floor: str = "medium"

    _CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def investigate(
        self,
        *,
        repo_path: str,
        budget: int,
    ) -> SourceExpertResult:
        """Scan ``repo_path`` applying family-filtered patterns."""
        root = Path(repo_path)
        if not root.is_dir():
            return SourceExpertResult(
                expert_id=self.expert_id,
                cwe_family=list(self.cwe_family),
                budget_available=budget,
                notes=[f"repo_path not a directory: {repo_path}"],
            )

        patterns = self._family_patterns()
        if not patterns:
            return SourceExpertResult(
                expert_id=self.expert_id,
                cwe_family=list(self.cwe_family),
                budget_available=budget,
                notes=["no patterns registered for this family"],
            )

        findings: list[Finding] = []
        files_scanned = 0
        notes: list[str] = []
        floor = self._CONFIDENCE_ORDER[self.confidence_floor]

        for path in _iter_sources(root):
            if files_scanned >= budget:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                notes.append(f"read failed {path.name}: {exc}")
                continue
            files_scanned += 1

            for rx, cwe, confidence, line_hint in patterns:
                if self._CONFIDENCE_ORDER.get(confidence, 1) < floor:
                    continue
                try:
                    for m in rx.finditer(text):
                        fn_hint = _function_containing(text, m.start())
                        line_no = text.count("\n", 0, m.start()) + 1
                        findings.append(Finding(
                            file_path=str(path),
                            function_name=fn_hint or "",
                            crash_type="",
                            cwe=cwe,
                            poc_source="",  # hunter / validator may fill
                            repo_path=str(root),
                            line_range=f"{line_no}-{line_no}",
                            severity=self._severity_hint(cwe, confidence),
                            language=_language_for(path),
                        ))
                        # At most one finding per (file, cwe, line): we
                        # want to surface diverse sites, not 20 hits on
                        # the same unsafe call.
                        break
                except re.error as exc:
                    notes.append(f"bad regex for {cwe}: {exc}")

        return SourceExpertResult(
            expert_id=self.expert_id,
            cwe_family=list(self.cwe_family),
            findings=findings,
            files_scanned=files_scanned,
            patterns_applied=len(patterns),
            budget_used=files_scanned,
            budget_available=budget,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Internals (overridable)
    # ------------------------------------------------------------------

    def _family_patterns(self) -> list[tuple[re.Pattern, str, str, str]]:
        """Return (compiled_regex, cwe, confidence, doc_hint) filtered to
        this expert's :attr:`cwe_family`. Bad YAML regexes are skipped."""
        out: list[tuple[re.Pattern, str, str, str]] = []
        family = set(self.cwe_family)
        for entry in iter_all_patterns():
            cwe = entry.get("cwe", "")
            if cwe not in family:
                continue
            for det in (entry.get("detection") or []):
                if not isinstance(det, dict):
                    continue
                raw = det.get("regex")
                if not raw:
                    continue
                try:
                    rx = re.compile(raw)
                except re.error:
                    continue
                out.append((
                    rx,
                    cwe,
                    det.get("confidence", "medium"),
                    det.get("rule_id", ""),
                ))
        return out

    def _severity_hint(self, cwe: str, confidence: str) -> str:
        """Initial severity guess — the validator will reclassify after
        reproduction. Heap overflows = HIGH by default; guesses drop a
        level when the detector confidence itself was low."""
        base = {
            "CWE-787": "HIGH",
            "CWE-122": "HIGH",
            "CWE-121": "HIGH",
            "CWE-125": "MEDIUM",
            "CWE-416": "CRITICAL",
            "CWE-190": "MEDIUM",
            "CWE-191": "MEDIUM",
            "CWE-369": "LOW",
            "CWE-78":  "HIGH",
            "CWE-89":  "HIGH",
            "CWE-94":  "CRITICAL",
            "CWE-134": "MEDIUM",
        }.get(cwe, "MEDIUM")
        if confidence == "low":
            base = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW"}.get(base, base)
        return base


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _iter_sources(root: Path) -> Iterator[Path]:
    """Walk the repo yielding source files, skipping common noise dirs."""
    SKIP = {".git", "node_modules", "build", "dist", "third_party", "__pycache__"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP for part in path.parts):
            continue
        if path.suffix.lower() in _SOURCE_SUFFIXES:
            yield path


# Heuristic: find the function definition preceding `offset`. Matches
# either C-style `ret func(` or C++-style `ret ClassName::func(`.
_FUNC_RE = re.compile(
    r"(?:^|\n)\s*(?:static\s+|inline\s+|extern\s+|const\s+)*"
    r"[A-Za-z_][\w*\s]*?"
    r"(?P<name>[A-Za-z_]\w+)\s*\([^;{}]*\)\s*\{",
    re.MULTILINE,
)


def _function_containing(text: str, offset: int) -> str:
    """Return the innermost function name enclosing `offset`, or ''."""
    last_name = ""
    for m in _FUNC_RE.finditer(text):
        if m.start() > offset:
            break
        last_name = m.group("name")
    return last_name


def _language_for(path: Path) -> str:
    s = path.suffix.lower()
    if s in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}:
        return "cpp"
    if s in {".m", ".mm"}:
        return "objc"
    return "c"


__all__ = ["SourceExpert", "SourceExpertResult"]
