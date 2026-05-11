"""TDD contract for kryon.learning.skill_scorer.

Pure tests — Wilson lower bound math + experience aggregation. No DB.
ChromaDB-backed end-to-end (`score_all_from_store`) lives in a separate
test guarded by `pytest.importorskip("chromadb")`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

# ---------- Helpers ----------


def _experience(
    *,
    agent_path: list[str],
    outcome: str = "success",
    chain_len: int = 3,
    created_at: str | None = None,
) -> dict[str, Any]:
    return {
        "id": f"eng_{outcome}_{len(agent_path)}",
        "agent_path": agent_path,
        "outcome": outcome,
        "chain": [{"tool": f"t{i}"} for i in range(chain_len)],
        "duration_s": 60,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
    }


# ---------- SkillScore dataclass ----------


def test_skill_score_is_frozen() -> None:
    from dataclasses import FrozenInstanceError

    from kryon.learning.skill_scorer import SkillScore

    score = SkillScore(skill_name="x", sample_size=0)
    with pytest.raises(FrozenInstanceError):
        score.sample_size = 5  # type: ignore[misc]


def test_skill_score_default_fields() -> None:
    """A skill with zero engagements still constructs cleanly."""
    from kryon.learning.skill_scorer import SkillScore

    s = SkillScore(skill_name="cold-start")
    assert s.sample_size == 0
    assert s.success_count == 0
    assert s.partial_count == 0
    assert s.fail_count == 0
    assert s.win_rate == 0.0
    assert s.confidence_lower == 0.0
    assert s.last_used is None


# ---------- Wilson lower bound (math) ----------


def test_wilson_zero_sample_returns_zero() -> None:
    from kryon.learning.skill_scorer import wilson_lower_bound

    assert wilson_lower_bound(successes=0, total=0) == 0.0


def test_wilson_perfect_record_low_n_still_below_one() -> None:
    """5/5 wins should not give 1.0 — small sample uncertainty matters."""
    from kryon.learning.skill_scorer import wilson_lower_bound

    bound = wilson_lower_bound(successes=5, total=5)
    assert 0.4 < bound < 0.95


def test_wilson_perfect_record_high_n_approaches_one() -> None:
    """100/100 wins → confidence approaches but never reaches 1."""
    from kryon.learning.skill_scorer import wilson_lower_bound

    bound = wilson_lower_bound(successes=100, total=100)
    assert bound > 0.95
    assert bound < 1.0


def test_wilson_balanced_record_close_to_half() -> None:
    from kryon.learning.skill_scorer import wilson_lower_bound

    bound = wilson_lower_bound(successes=50, total=100)
    assert 0.40 < bound < 0.50  # below the point estimate of 0.5


def test_wilson_zero_successes_returns_zero() -> None:
    from kryon.learning.skill_scorer import wilson_lower_bound

    assert wilson_lower_bound(successes=0, total=20) == 0.0


def test_wilson_more_data_tightens_bound_for_same_rate() -> None:
    """Same win rate (0.8) — more samples → tighter (higher) lower bound."""
    from kryon.learning.skill_scorer import wilson_lower_bound

    low_n = wilson_lower_bound(successes=4, total=5)
    high_n = wilson_lower_bound(successes=80, total=100)
    assert high_n > low_n


# ---------- Aggregation: score_skills ----------


def test_score_skills_no_skill_names_returns_empty_dict() -> None:
    from kryon.learning.skill_scorer import score_skills

    assert score_skills(experiences=[], skill_names=[]) == {}


def test_score_skills_cold_start_gives_zero_sample_scores() -> None:
    """No experiences yet — every requested skill gets a placeholder score."""
    from kryon.learning.skill_scorer import score_skills

    out = score_skills(experiences=[], skill_names=["alpha", "beta"])
    assert set(out.keys()) == {"alpha", "beta"}
    assert all(s.sample_size == 0 for s in out.values())
    assert all(s.win_rate == 0.0 for s in out.values())


def test_score_skills_counts_outcomes() -> None:
    from kryon.learning.skill_scorer import score_skills

    exps = [
        _experience(agent_path=["unifi-audit"], outcome="success"),
        _experience(agent_path=["unifi-audit"], outcome="success"),
        _experience(agent_path=["unifi-audit"], outcome="partial"),
        _experience(agent_path=["unifi-audit"], outcome="fail"),
    ]
    out = score_skills(experiences=exps, skill_names=["unifi-audit"])
    s = out["unifi-audit"]
    assert s.sample_size == 4
    assert s.success_count == 2
    assert s.partial_count == 1
    assert s.fail_count == 1


def test_score_skills_recon_only_counts_as_fail() -> None:
    """For win-rate purposes, recon-only is non-actionable → counts as fail."""
    from kryon.learning.skill_scorer import score_skills

    exps = [
        _experience(agent_path=["recon-scout"], outcome="recon-only"),
        _experience(agent_path=["recon-scout"], outcome="recon-only"),
    ]
    out = score_skills(experiences=exps, skill_names=["recon-scout"])
    assert out["recon-scout"].fail_count == 2
    assert out["recon-scout"].success_count == 0


def test_score_skills_attributes_to_every_skill_in_agent_path() -> None:
    """An engagement with multiple active skills credits each one."""
    from kryon.learning.skill_scorer import score_skills

    exps = [
        _experience(agent_path=["fortigate-audit", "recon-scout"], outcome="success"),
    ]
    out = score_skills(experiences=exps, skill_names=["fortigate-audit", "recon-scout"])
    assert out["fortigate-audit"].sample_size == 1
    assert out["recon-scout"].sample_size == 1


def test_score_skills_win_rate_treats_partial_as_half() -> None:
    """Partial outcome contributes 0.5 to win rate — not as good as
    success but better than fail. This matches the synthesizer's
    quality bar (partial qualifies for drafts)."""
    from kryon.learning.skill_scorer import score_skills

    exps = [
        _experience(agent_path=["x"], outcome="success"),  # 1.0
        _experience(agent_path=["x"], outcome="partial"),  # 0.5
        _experience(agent_path=["x"], outcome="fail"),  # 0.0
    ]
    out = score_skills(experiences=exps, skill_names=["x"])
    # (1.0 + 0.5 + 0.0) / 3 = 0.5
    assert out["x"].win_rate == pytest.approx(0.5)


def test_score_skills_tracks_last_used() -> None:
    from kryon.learning.skill_scorer import score_skills

    older = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    newer = datetime.now(timezone.utc).isoformat()
    exps = [
        _experience(agent_path=["x"], outcome="success", created_at=older),
        _experience(agent_path=["x"], outcome="success", created_at=newer),
    ]
    out = score_skills(experiences=exps, skill_names=["x"])
    assert out["x"].last_used == newer  # the latest timestamp wins


def test_score_skills_avg_chain_len_computed() -> None:
    from kryon.learning.skill_scorer import score_skills

    exps = [
        _experience(agent_path=["x"], outcome="success", chain_len=4),
        _experience(agent_path=["x"], outcome="success", chain_len=8),
    ]
    out = score_skills(experiences=exps, skill_names=["x"])
    assert out["x"].avg_chain_len == pytest.approx(6.0)


# ---------- Confidence-aware ranking ----------


def test_low_confidence_when_sample_below_threshold() -> None:
    from kryon.learning.skill_scorer import score_skills

    exps = [
        _experience(agent_path=["fresh-skill"], outcome="success"),
        _experience(agent_path=["fresh-skill"], outcome="success"),
    ]
    out = score_skills(
        experiences=exps,
        skill_names=["fresh-skill"],
        min_sample_for_confidence=5,
    )
    s = out["fresh-skill"]
    assert s.sample_size == 2
    # Low-confidence flag exposed for the leaderboard UI.
    assert s.is_low_confidence is True


def test_high_confidence_when_sample_above_threshold() -> None:
    from kryon.learning.skill_scorer import score_skills

    exps = [_experience(agent_path=["mature"], outcome="success")] * 12
    out = score_skills(
        experiences=exps,
        skill_names=["mature"],
        min_sample_for_confidence=5,
    )
    assert out["mature"].is_low_confidence is False


# ---------- Hybrid ranking helper ----------


def test_rank_skills_hybrid_uses_priority_as_primary_sort() -> None:
    """Banking compliance: priority is THE law. Score only tie-breaks."""
    from kryon.learning.skill_scorer import (
        SkillScore,
        rank_skills_hybrid,
    )

    skills = [
        ("low-prio", 30),
        ("high-prio-bad", 10),
        ("high-prio-good", 10),
    ]
    scores = {
        "low-prio": SkillScore(
            skill_name="low-prio",
            sample_size=20,
            win_rate=0.95,
            confidence_lower=0.85,
            is_low_confidence=False,
        ),
        "high-prio-bad": SkillScore(
            skill_name="high-prio-bad",
            sample_size=20,
            win_rate=0.10,
            confidence_lower=0.05,
            is_low_confidence=False,
        ),
        "high-prio-good": SkillScore(
            skill_name="high-prio-good",
            sample_size=20,
            win_rate=0.90,
            confidence_lower=0.78,
            is_low_confidence=False,
        ),
    }
    ranked = rank_skills_hybrid(skills, scores)
    # Both priority-10 skills come first (regardless of score).
    assert ranked[0][0] in {"high-prio-bad", "high-prio-good"}
    assert ranked[1][0] in {"high-prio-bad", "high-prio-good"}
    # Within tier, the better score wins.
    assert ranked[0][0] == "high-prio-good"
    # Lower priority comes after, even with a great score.
    assert ranked[2][0] == "low-prio"


def test_rank_skills_score_mode_ignores_priority() -> None:
    """`score`-only ranking (rare — for experimentation, not banking)."""
    from kryon.learning.skill_scorer import (
        SkillScore,
        rank_skills_score_only,
    )

    skills = [("low-prio-good", 30), ("high-prio-bad", 10)]
    scores = {
        "low-prio-good": SkillScore(
            skill_name="low-prio-good",
            sample_size=20,
            win_rate=0.95,
            confidence_lower=0.85,
            is_low_confidence=False,
        ),
        "high-prio-bad": SkillScore(
            skill_name="high-prio-bad",
            sample_size=20,
            win_rate=0.10,
            confidence_lower=0.05,
            is_low_confidence=False,
        ),
    }
    ranked = rank_skills_score_only(skills, scores)
    # Score wins — priority ignored.
    assert ranked[0][0] == "low-prio-good"


def test_rank_skills_low_confidence_falls_back_to_priority_within_tier() -> None:
    """Two skills, same priority, but one is low-confidence and one isn't.
    The mature one wins even if the cold-starter has a higher raw win_rate."""
    from kryon.learning.skill_scorer import (
        SkillScore,
        rank_skills_hybrid,
    )

    skills = [("rookie", 20), ("veteran", 20)]
    scores = {
        "rookie": SkillScore(
            skill_name="rookie",
            sample_size=2,
            win_rate=1.0,
            confidence_lower=0.20,
            is_low_confidence=True,
        ),
        "veteran": SkillScore(
            skill_name="veteran",
            sample_size=50,
            win_rate=0.80,
            confidence_lower=0.70,
            is_low_confidence=False,
        ),
    }
    ranked = rank_skills_hybrid(skills, scores)
    assert ranked[0][0] == "veteran"
