"""The token budget must greedily PACK skills, not stop at the first overflow.

Regression (T3-A10): the loop used `break`, so a big skill mid-ranking evicted every
smaller, more-specific skill after it (wordpress-audit lost to a big generic one)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from kryon.skills.loader import SkillLoader


def _skill(base: Path, name: str, priority: int, body_chars: int) -> None:
    (base / f"{name}.md").write_text(
        textwrap.dedent(f"""\
        ---
        name: {name}
        description: x
        triggers:
          tech: []
          ports: []
          keywords: ["packkw"]
        priority: {priority}
        required_tools: []
        ---
        """)
        + ("x" * body_chars),
        encoding="utf-8",
    )


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    base = tmp_path / "playbooks"
    base.mkdir()
    _skill(base, "small_early", 10, 400)  # ~100 tok — fits
    _skill(base, "huge_middle", 20, 40000)  # ~10K tok — does NOT fit under 6000
    _skill(base, "small_late", 30, 400)  # ~100 tok — must still be packed
    return base


def test_big_skill_mid_ranking_does_not_evict_later_small_ones(skill_dir):
    loader = SkillLoader(skill_dirs=[skill_dir])
    matched = loader.match(user_msg="packkw audit", budget_tokens=6000)
    names = {s.name for s in matched}
    assert "small_early" in names
    assert "small_late" in names  # would be dropped by `break`
    assert "huge_middle" not in names  # correctly skipped (over budget)
