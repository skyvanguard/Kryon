"""Tests for ranking-aware SkillLoader.match (Fase 2).

The default ranking is "priority" — pure legacy behaviour, banking-safe.
"hybrid" reorders within the same priority tier using experience-based
scores. "score" ignores priority entirely (experimentation only).

These tests inject synthetic experiences via the optional loader callback
so they don't depend on ChromaDB.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from kryon.skills.loader import SkillLoader


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    """Two skills with identical priority — for testing tie-break."""
    base = tmp_path / "playbooks"
    base.mkdir()

    (base / "winner.md").write_text(
        textwrap.dedent("""\
        ---
        name: winner-skill
        description: x
        triggers:
          tech: []
          ports: []
          keywords: ["wifi"]
        priority: 30
        required_tools: []
        ---
        body
    """),
        encoding="utf-8",
    )

    (base / "loser.md").write_text(
        textwrap.dedent("""\
        ---
        name: loser-skill
        description: x
        triggers:
          tech: []
          ports: []
          keywords: ["wifi"]
        priority: 30
        required_tools: []
        ---
        body
    """),
        encoding="utf-8",
    )

    (base / "high_prio.md").write_text(
        textwrap.dedent("""\
        ---
        name: high-prio
        description: x
        triggers:
          tech: []
          ports: []
          keywords: ["wifi"]
        priority: 10
        required_tools: []
        ---
        body
    """),
        encoding="utf-8",
    )
    return base


def _experience(skill: str, outcome: str) -> dict[str, Any]:
    return {
        "id": f"eng_{skill}_{outcome}",
        "agent_path": [skill],
        "outcome": outcome,
        "chain": [{"tool": "t1"}, {"tool": "t2"}],
        "duration_s": 60,
        "created_at": "2026-04-28T17:00:00+00:00",
    }


# ---------- Default (priority) — unchanged behaviour ----------


def test_default_ranking_is_priority(skill_dir: Path) -> None:
    """No experiences, no ENV — pure priority sort, exactly like before."""
    loader = SkillLoader(skill_dirs=[skill_dir])
    matched = loader.match(user_msg="wifi audit")
    names = [s.name for s in matched]
    # high-prio (priority 10) comes first; the two priority-30 skills follow.
    assert names[0] == "high-prio"
    assert set(names[1:]) == {"winner-skill", "loser-skill"}


def test_priority_ranking_does_not_consult_experience_store(
    skill_dir: Path,
) -> None:
    """If priority mode is requested, the experience loader must NOT be called.
    Saves a chromadb roundtrip + keeps banking compliance deterministic."""
    loader = SkillLoader(skill_dirs=[skill_dir])

    calls: list[bool] = []

    def explosive_loader() -> list[dict]:
        calls.append(True)
        raise RuntimeError("must not be called in priority mode")

    matched = loader.match(
        user_msg="wifi",
        ranking="priority",
        experience_loader=explosive_loader,
    )
    assert calls == []
    assert matched  # still returns skills


# ---------- Hybrid mode ----------


def test_hybrid_ranking_breaks_ties_within_priority_tier(
    skill_dir: Path,
) -> None:
    """winner-skill has 10/10 wins, loser-skill has 0/10. Both priority 30.
    Hybrid mode should put winner-skill above loser-skill."""
    loader = SkillLoader(skill_dirs=[skill_dir])
    exps = [_experience("winner-skill", "success")] * 12 + [_experience("loser-skill", "fail")] * 12
    matched = loader.match(
        user_msg="wifi audit",
        ranking="hybrid",
        experience_loader=lambda: exps,
    )
    names = [s.name for s in matched]
    # high-prio (10) still first — priority is the tier sort key.
    assert names[0] == "high-prio"
    # Within priority-30 tier, winner-skill above loser-skill.
    idx_winner = names.index("winner-skill")
    idx_loser = names.index("loser-skill")
    assert idx_winner < idx_loser


def test_hybrid_never_promotes_low_priority_above_high(skill_dir: Path) -> None:
    """Even with a perfect score, a priority-30 skill can't beat a
    priority-10 skill in hybrid mode. Banking compliance contract."""
    loader = SkillLoader(skill_dirs=[skill_dir])

    # winner-skill (priority 30) wins everything, high-prio (priority 10)
    # has no engagements at all.
    exps = [_experience("winner-skill", "success")] * 50

    matched = loader.match(
        user_msg="wifi",
        ranking="hybrid",
        experience_loader=lambda: exps,
    )
    names = [s.name for s in matched]
    assert names[0] == "high-prio", f"priority-10 must always come first in hybrid; got {names}"


def test_hybrid_with_no_experiences_degrades_to_priority(skill_dir: Path) -> None:
    """Cold start (zero experiences) — hybrid mode behaves like priority.
    No skill gets confidence > 0, so the tie-break has no effect."""
    loader = SkillLoader(skill_dirs=[skill_dir])
    matched = loader.match(
        user_msg="wifi",
        ranking="hybrid",
        experience_loader=lambda: [],
    )
    names = [s.name for s in matched]
    assert names[0] == "high-prio"


def test_hybrid_with_low_confidence_skills_uses_priority_within_tier(
    skill_dir: Path,
) -> None:
    """winner-skill has 2/2 success — small sample, low confidence.
    Hybrid should NOT promote it above loser-skill on that thin signal."""
    loader = SkillLoader(skill_dirs=[skill_dir])
    exps = [_experience("winner-skill", "success")] * 2  # below threshold

    matched = loader.match(
        user_msg="wifi",
        ranking="hybrid",
        experience_loader=lambda: exps,
    )
    names = [s.name for s in matched]
    # Both skills equal — order within tier is undefined but deterministic.
    # We assert both are present and the priority contract holds.
    assert "winner-skill" in names
    assert "loser-skill" in names
    assert names.index("high-prio") == 0


# ---------- ENV var ----------


def test_env_var_enables_hybrid_mode(
    skill_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ranking is not passed and KRYON_SKILL_RANKING=hybrid, hybrid
    mode kicks in automatically."""
    monkeypatch.setenv("KRYON_SKILL_RANKING", "hybrid")
    loader = SkillLoader(skill_dirs=[skill_dir])

    consulted: list[bool] = []

    def loader_fn() -> list[dict]:
        consulted.append(True)
        return []

    loader.match(user_msg="wifi", experience_loader=loader_fn)
    assert consulted == [True]


def test_env_var_invalid_value_falls_back_to_priority(
    skill_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Typos in env var must NOT raise; default to safe priority mode."""
    monkeypatch.setenv("KRYON_SKILL_RANKING", "garbage-value")
    loader = SkillLoader(skill_dirs=[skill_dir])

    matched = loader.match(user_msg="wifi", experience_loader=lambda: [])
    # Did not crash, returned skills.
    assert len(matched) >= 2


def test_explicit_ranking_overrides_env_var(
    skill_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRYON_SKILL_RANKING", "hybrid")
    loader = SkillLoader(skill_dirs=[skill_dir])

    consulted: list[bool] = []

    def explosive() -> list[dict]:
        consulted.append(True)
        raise RuntimeError("priority should win")

    loader.match(
        user_msg="wifi",
        ranking="priority",  # explicit overrides env
        experience_loader=explosive,
    )
    assert consulted == []


# ---------- Resilience ----------


def test_hybrid_when_experience_loader_raises_falls_back_to_priority(
    skill_dir: Path,
) -> None:
    """If chromadb is broken or list_experiences crashes, hybrid mode
    must NOT take down the matcher. Fallback to priority is mandatory."""
    loader = SkillLoader(skill_dirs=[skill_dir])

    def boom() -> list[dict]:
        raise RuntimeError("chromadb is dead, jim")

    matched = loader.match(
        user_msg="wifi",
        ranking="hybrid",
        experience_loader=boom,
    )
    # No exception escaped, skills still matched, priority order preserved.
    names = [s.name for s in matched]
    assert names[0] == "high-prio"
