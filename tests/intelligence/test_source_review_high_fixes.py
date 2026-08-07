"""Regression tests for the HIGH source-review fixes:
- wall-clock deadline stops the review loop early (no multi-hour hangs)
- variant expansion is capped by variant_max_files
- distinct lines in the same file get distinct downstream rule_ids
"""

from __future__ import annotations

from pathlib import Path

from kryon.intelligence.source_review import (
    SourceFinding,
    review_tree,
)


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class _StepClock:
    """Deterministic clock that advances a fixed step on every call."""

    def __init__(self, step: float = 10.0) -> None:
        self.t = 0.0
        self.step = step

    def __call__(self) -> float:
        v = self.t
        self.t += self.step
        return v


def test_wall_budget_stops_primary_loop_early(tmp_path: Path) -> None:
    for i in range(4):
        _write(tmp_path / f"f{i}.py", "os.system(x)\n" * 3)

    seen: list[str] = []

    def reviewer(rel: str, code: str) -> list[SourceFinding]:
        seen.append(rel)
        return []

    # step 10, budget 15: t0=0, file0 ok (clock→10, 10<15), then clock→20>15 → break.
    result = review_tree(
        tmp_path,
        reviewer=reviewer,
        variant_analysis=False,
        wall_budget_s=15.0,
        clock=_StepClock(10.0),
    )
    assert result.files_reviewed < 4, "budget should have cut the loop short"
    assert any("wall budget" in e for e in result.errors)


def test_variant_expansion_is_capped(tmp_path: Path) -> None:
    # 4 files all carrying the same sink; primary reviews 1, variant should
    # add at most variant_max_files=1 more.
    for i in range(4):
        _write(tmp_path / f"f{i}.py", "os.system(user_input)\n")

    def reviewer(rel: str, code: str) -> list[SourceFinding]:
        if "os.system" in code:
            return [
                SourceFinding(
                    file=rel,
                    line=1,
                    cwe="CWE-78",
                    severity="HIGH",
                    title="cmd injection",
                    sink="os.system(",
                    confidence=0.9,
                )
            ]
        return []

    result = review_tree(
        tmp_path,
        reviewer=reviewer,
        max_files=1,
        variant_max_files=1,
    )
    assert result.variant_files_reviewed <= 1


def test_distinct_lines_get_distinct_rule_ids() -> None:
    common = dict(file="app.py", cwe="CWE-89", severity="HIGH", title="SQLi")
    f1 = SourceFinding(line=40, **common)
    f2 = SourceFinding(line=120, **common)
    r1 = f1.to_engage_finding().rule_id
    r2 = f2.to_engage_finding().rule_id
    assert r1 != r2, "same-file, different-line findings must not share a rule_id"
    assert r1 == "SAST-CWE-89-L40"
    assert r2 == "SAST-CWE-89-L120"
