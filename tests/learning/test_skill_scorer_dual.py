"""F77.G.5 — TDD contract for the SAGE dual-reward extension of
skill_scorer.

We don't re-test the Wilson lower bound here (that lives in
test_skill_scorer.py). The focus is:

  - reusability_from_telemetry counts distinct records correctly
  - normalization maps to [0, 1]
  - score_skills with telemetry populates the new fields, without
    breaking the legacy no-telemetry path
  - combined_score uses the documented weights
  - low-confidence skills suppress their Wilson contribution but
    still carry the reusability axis
  - rank_skills_dual keeps priority as the primary sort (banking-
    safety contract)
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

import pytest

from kryon.learning.skill_scorer import (
    SkillScore,
    _normalize_counts,
    rank_skills_dual,
    rank_skills_hybrid,
    reusability_from_telemetry,
    score_skills,
)


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


def _record(selected: list[str]) -> dict[str, Any]:
    return {"ts": "2026-05-13T00:00:00Z", "selected": selected}


# =====================================================================
# reusability_from_telemetry
# =====================================================================


def test_reusability_counts_distinct_records():
    records = [
        _record(["skill_a", "skill_b"]),
        _record(["skill_a"]),
        _record(["skill_c"]),
    ]
    counts = reusability_from_telemetry(records, ["skill_a", "skill_b", "skill_c"])
    assert counts == {"skill_a": 2, "skill_b": 1, "skill_c": 1}


def test_reusability_dedupes_within_record():
    """A single log record selecting the same skill twice (defensive —
    shouldn't happen today but might if the contract changes) counts
    as one."""
    records = [_record(["skill_a", "skill_a", "skill_b"])]
    counts = reusability_from_telemetry(records, ["skill_a", "skill_b"])
    assert counts == {"skill_a": 1, "skill_b": 1}


def test_reusability_drops_unrequested_skills():
    """Skills not in `skill_names` must not appear in the output dict —
    the caller should never have to filter."""
    records = [_record(["skill_a", "skill_b", "irrelevant"])]
    counts = reusability_from_telemetry(records, ["skill_a"])
    assert counts == {"skill_a": 1}
    assert "irrelevant" not in counts


def test_reusability_empty_records():
    counts = reusability_from_telemetry([], ["skill_a"])
    assert counts == {"skill_a": 0}


def test_reusability_handles_malformed_records():
    """Records with non-list selected should be skipped, not crash."""
    records = [
        {"selected": None},
        {"selected": "not_a_list"},
        {},  # no 'selected' key
        _record(["skill_a"]),
    ]
    counts = reusability_from_telemetry(records, ["skill_a"])
    assert counts == {"skill_a": 1}


# =====================================================================
# _normalize_counts
# =====================================================================


def test_normalize_maps_to_unit_interval():
    norms = _normalize_counts({"a": 10, "b": 5, "c": 0})
    assert norms["a"] == 1.0
    assert math.isclose(norms["b"], 0.5)
    assert norms["c"] == 0.0


def test_normalize_all_zero_returns_zeros():
    """All-zero counts must not divide by zero."""
    assert _normalize_counts({"a": 0, "b": 0}) == {"a": 0.0, "b": 0.0}


def test_normalize_empty_dict():
    assert _normalize_counts({}) == {}


# =====================================================================
# score_skills with telemetry
# =====================================================================


def test_score_skills_without_telemetry_is_legacy_path():
    """Backward-compat: omitting telemetry_records must produce zero
    reusability fields. This protects every existing caller that
    didn't pass the kwarg."""
    exps = [_experience(agent_path=["pentest"]) for _ in range(10)]
    scores = score_skills(exps, ["pentest"])
    s = scores["pentest"]
    assert s.reusability_count == 0
    assert s.reusability_norm == 0.0
    # combined_score is wilson * 0.7 + 0 — equals wilson * 0.7
    assert math.isclose(s.combined_score, 0.7 * s.confidence_lower, abs_tol=1e-9)


def test_score_skills_with_telemetry_populates_reusability_fields():
    exps = [_experience(agent_path=["pentest"]) for _ in range(10)]
    records = [_record(["pentest"]) for _ in range(5)] + [_record(["other"]) for _ in range(2)]
    scores = score_skills(exps, ["pentest", "other"], telemetry_records=records)
    assert scores["pentest"].reusability_count == 5
    # pentest is the max (5 vs 2) → norm = 1.0
    assert scores["pentest"].reusability_norm == 1.0
    # other had no experiences → sample_size 0, but reusability is recorded
    assert scores["other"].sample_size == 0
    assert scores["other"].reusability_count == 2
    assert math.isclose(scores["other"].reusability_norm, 0.4)


def test_combined_score_formula():
    """Pin the 0.7 * wilson + 0.3 * reuse blend so a future weight
    tweak forces an intentional update here + the docs."""
    exps = [_experience(agent_path=["pentest"]) for _ in range(20)]
    records = [_record(["pentest"]) for _ in range(10)]
    scores = score_skills(exps, ["pentest"], telemetry_records=records)
    s = scores["pentest"]
    expected = 0.7 * s.confidence_lower + 0.3 * s.reusability_norm
    assert math.isclose(s.combined_score, expected, abs_tol=1e-9)


def test_low_confidence_skill_suppresses_wilson_in_combined():
    """A skill with only 3 engagements is low-confidence. Its combined
    score must NOT include the Wilson component (the interval is too
    wide to trust); only the reusability axis contributes."""
    exps = [_experience(agent_path=["new_skill"]) for _ in range(3)]
    records = [_record(["new_skill"]) for _ in range(5)]
    scores = score_skills(exps, ["new_skill"], telemetry_records=records)
    s = scores["new_skill"]
    assert s.is_low_confidence is True
    # combined = 0 * 0.7 (suppressed) + 1.0 * 0.3 (reuse_norm is 1 since it's the only skill)
    assert math.isclose(s.combined_score, 0.3, abs_tol=1e-9)


def test_zero_engagement_skill_with_reusability():
    """Edge case: skill appears in telemetry but has no engagements.
    Should not crash. combined_score reflects reusability only."""
    records = [_record(["ghost"])]
    scores = score_skills([], ["ghost"], telemetry_records=records)
    s = scores["ghost"]
    assert s.sample_size == 0
    assert s.confidence_lower == 0.0
    assert s.reusability_count == 1
    assert math.isclose(s.combined_score, 0.3, abs_tol=1e-9)


def test_custom_weights_are_respected():
    """Operator can override the 0.7/0.3 split via kwargs. Verifies
    score_skills passes them through to the combined_score
    calculation."""
    exps = [_experience(agent_path=["x"]) for _ in range(20)]
    records = [_record(["x"]) for _ in range(10)]
    scores = score_skills(
        exps,
        ["x"],
        telemetry_records=records,
        wilson_weight=0.5,
        reuse_weight=0.5,
    )
    s = scores["x"]
    expected = 0.5 * s.confidence_lower + 0.5 * s.reusability_norm
    assert math.isclose(s.combined_score, expected, abs_tol=1e-9)


# =====================================================================
# rank_skills_dual — banking-safety: priority dominates
# =====================================================================


def test_dual_ranker_respects_priority_tiers():
    """Banca-safety: a high-combined-score skill at priority 50 MUST
    NOT outrank a low-combined-score skill at priority 10."""
    # Cooked SkillScore objects bypassing score_skills for unit-test
    # determinism.
    scores = {
        "high_score_low_priority": SkillScore(
            skill_name="high_score_low_priority",
            sample_size=20,
            success_count=20,
            confidence_lower=0.9,
            combined_score=0.9,
            is_low_confidence=False,
        ),
        "low_score_high_priority": SkillScore(
            skill_name="low_score_high_priority",
            sample_size=20,
            success_count=5,
            confidence_lower=0.1,
            combined_score=0.1,
            is_low_confidence=False,
        ),
    }
    pairs = [("high_score_low_priority", 50), ("low_score_high_priority", 10)]
    ranked = rank_skills_dual(pairs, scores)
    assert ranked[0][0] == "low_score_high_priority"
    assert ranked[1][0] == "high_score_low_priority"


def test_dual_ranker_orders_within_priority_tier():
    """Two skills at the same priority tier — combined_score
    breaks the tie."""
    scores = {
        "a": SkillScore(
            skill_name="a", sample_size=20, combined_score=0.3, is_low_confidence=False
        ),
        "b": SkillScore(
            skill_name="b", sample_size=20, combined_score=0.7, is_low_confidence=False
        ),
        "c": SkillScore(
            skill_name="c", sample_size=20, combined_score=0.5, is_low_confidence=False
        ),
    }
    pairs = [("a", 10), ("b", 10), ("c", 10)]
    ranked = rank_skills_dual(pairs, scores)
    assert [n for n, _ in ranked] == ["b", "c", "a"]


def test_dual_ranker_handles_missing_score():
    """A skill not in the scores dict must not crash the ranker."""
    pairs = [("never_seen", 10), ("known", 10)]
    scores = {
        "known": SkillScore(
            skill_name="known", sample_size=20, combined_score=0.5, is_low_confidence=False
        ),
    }
    ranked = rank_skills_dual(pairs, scores)
    # known has score 0.5, never_seen treated as 0 — known first.
    assert ranked[0][0] == "known"


def test_dual_and_hybrid_diverge_on_reuse_tie_break():
    """Two same-priority skills with similar Wilson but different
    reuse counts should diverge between hybrid and dual rankings —
    proves the new axis actually changes decisions."""
    scores = {
        "veteran": SkillScore(
            skill_name="veteran",
            sample_size=50,
            confidence_lower=0.65,
            reusability_norm=0.0,
            combined_score=0.7 * 0.65 + 0.3 * 0.0,
            is_low_confidence=False,
        ),
        "rising_star": SkillScore(
            skill_name="rising_star",
            sample_size=50,
            confidence_lower=0.60,
            reusability_norm=1.0,
            combined_score=0.7 * 0.60 + 0.3 * 1.0,  # = 0.72 — beats veteran's 0.455
            is_low_confidence=False,
        ),
    }
    pairs = [("veteran", 10), ("rising_star", 10)]
    hybrid_ranked = rank_skills_hybrid(pairs, scores)
    dual_ranked = rank_skills_dual(pairs, scores)
    # hybrid sorts on confidence_lower → veteran first
    assert hybrid_ranked[0][0] == "veteran"
    # dual sorts on combined_score → rising_star first (reuse boost)
    assert dual_ranked[0][0] == "rising_star"
