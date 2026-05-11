"""NumericExpert — CWE-190 / CWE-191 / CWE-369.

Integer overflow (190), integer underflow (191), divide-by-zero (369).
We override the base scan to also do an upper-bound guard check before
emitting: most numeric patterns in the library match e.g. `recv(...);
for (i=0; i<=n; i++)` — a real finding has no upper bound on `n`, but a
guarded one has `if (n > SIZE_MAX/4)` nearby. Keeps FPR low on codebases
that do validate before arithmetic.
"""

from __future__ import annotations

import re
from pathlib import Path

from kryon.skills.experts_sourcecode.base import (
    SourceExpert,
    SourceExpertResult,
    _function_containing,
    _iter_sources,
    _language_for,
)
from kryon.skills.validator_agent import Finding

# Simple upper-bound indicator — if any of these appear within 10 lines
# BEFORE the match, we assume the arithmetic was validated.
_BOUND_MARKERS = re.compile(
    r"\b(?:if|assert)\s*\([^)]*(?:<\s*[A-Z_]+_MAX|<=\s*[A-Z_]+_MAX|< 0x|INT_MAX|SIZE_MAX|UINT_MAX)",
)


class NumericExpert(SourceExpert):
    expert_id = "numeric"
    cwe_family = ("CWE-190", "CWE-191", "CWE-369")
    max_budget = 40
    confidence_floor = "medium"

    def investigate(
        self,
        *,
        repo_path: str,
        budget: int,
    ) -> SourceExpertResult:
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
                notes=["no patterns for numeric family"],
            )

        findings: list[Finding] = []
        files_scanned = 0
        notes: list[str] = []
        floor = self._CONFIDENCE_ORDER[self.confidence_floor]
        guarded = 0

        for path in _iter_sources(root):
            if files_scanned >= budget:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                notes.append(f"read failed {path.name}: {exc}")
                continue
            files_scanned += 1
            lines = text.splitlines()

            for rx, cwe, confidence, _rule in patterns:
                if self._CONFIDENCE_ORDER.get(confidence, 1) < floor:
                    continue
                for m in rx.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    # Lookup 10 preceding lines for an upper-bound guard.
                    start = max(0, line_no - 11)
                    context = "\n".join(lines[start:line_no - 1])
                    if _BOUND_MARKERS.search(context):
                        guarded += 1
                        continue
                    findings.append(Finding(
                        file_path=str(path),
                        function_name=_function_containing(text, m.start()) or "",
                        crash_type="",
                        cwe=cwe,
                        poc_source="",
                        repo_path=str(root),
                        line_range=f"{line_no}-{line_no}",
                        severity=self._severity_hint(cwe, confidence),
                        language=_language_for(path),
                    ))
                    break  # at most one finding per (file, regex)

        if guarded:
            notes.append(f"filtered {guarded} matches with upper-bound guards")

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


__all__ = ["NumericExpert"]
