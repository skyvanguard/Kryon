"""Skill scoring — per-skill win rate with Wilson confidence intervals.

Pure aggregation over a list of experience dicts. The caller supplies
the list (typically from `kryon.learning.list_experiences()`) and the
set of skill names to score; this module never touches ChromaDB itself.

The score combines:
  - `win_rate` — point estimate (success + 0.5 * partial) / total.
    Partial counts at half because the synthesizer accepts it as
    "draftable", but we don't conflate it with hard wins.
  - `confidence_lower` — 95% Wilson lower bound on the success rate.
    With small samples this is far below the point estimate, which
    keeps a 5/5-cold-starter from leapfrogging a 80/100-veteran.
  - `is_low_confidence` — flag for skills below `min_sample_for_confidence`.
    Used by both the leaderboard UI and the hybrid ranker.

Two ranking helpers:
  - `rank_skills_hybrid` — primary sort by priority (the SkillLoader's
    legacy contract; banking compliance respects this), then by score
    within the same priority tier. SAFE default for production.
  - `rank_skills_score_only` — ignore priority entirely. Reserved for
    experimentation; not used by the loader's hybrid mode.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


# Z-score for a 95% confidence interval (two-sided).
_Z_95 = 1.96

# A skill needs at least this many engagements to receive a "trusted" score.
# Below it, hybrid ranking falls back to priority within the same tier.
_DEFAULT_MIN_SAMPLE = 10


@dataclass(frozen=True)
class SkillScore:
    """One skill's aggregate performance over the experience corpus."""

    skill_name: str
    sample_size: int = 0
    success_count: int = 0
    partial_count: int = 0
    fail_count: int = 0
    win_rate: float = 0.0
    confidence_lower: float = 0.0
    avg_chain_len: float = 0.0
    last_used: str | None = None
    is_low_confidence: bool = True


def wilson_lower_bound(
    successes: int | float,
    total: int | float,
    z: float = _Z_95,
) -> float:
    """95% Wilson lower bound on the underlying success rate.

    Returns 0.0 for empty / no-success inputs to match the leaderboard's
    "show nothing for cold-starters" semantics.

    Reference: Wilson 1927; this is the same formula reddit/HN/etc. use
    for "best" rankings.
    """
    if total <= 0 or successes <= 0:
        return 0.0
    p = successes / total
    n = total
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2 * n)) / denom
    margin = (z * math.sqrt((p * (1 - p) / n) + (z * z) / (4 * n * n))) / denom
    return max(0.0, center - margin)


def _classify_outcome(outcome: str) -> str:
    """Bucket the four chain_extractor outcomes into win/partial/fail."""
    if outcome == "success":
        return "success"
    if outcome == "partial":
        return "partial"
    # `recon-only` and `fail` both contribute zero to the win rate.
    return "fail"


def _agent_path_skills(experience: dict[str, Any]) -> list[str]:
    """Extract the list of skill names credited for this engagement.

    Accepts both list (canonical, from chain_extractor) and comma-
    separated string (the metadata-flattened shape that
    `experiences._metadata_to_experience` rehydrates).
    """
    raw = experience.get("agent_path") or []
    if isinstance(raw, str):
        return [s.strip() for s in raw.split(",") if s.strip()]
    return [str(s) for s in raw if s]


def score_skills(
    experiences: list[dict[str, Any]],
    skill_names: list[str],
    *,
    min_sample_for_confidence: int = _DEFAULT_MIN_SAMPLE,
) -> dict[str, SkillScore]:
    """Aggregate experiences into per-skill SkillScore entries.

    Args:
        experiences: list of experience dicts (from `list_experiences()`
            or any source matching the same shape).
        skill_names: skills to score — must be the union of skills the
            caller cares about. Skills not in this list are dropped.
            Skills in the list with zero engagements get a zero-sample
            placeholder score (so the leaderboard shows them too).
        min_sample_for_confidence: threshold below which the score is
            flagged `is_low_confidence=True`.

    Returns:
        dict keyed by skill name → SkillScore.
    """
    if not skill_names:
        return {}

    requested = set(skill_names)

    # Per-skill counters
    counts: dict[str, dict[str, Any]] = {
        name: {
            "success": 0,
            "partial": 0,
            "fail": 0,
            "chain_len_sum": 0,
            "last_used": None,
        }
        for name in requested
    }

    for exp in experiences:
        outcome = _classify_outcome(exp.get("outcome", "fail"))
        chain_len = len(exp.get("chain") or [])
        created_at = exp.get("created_at")

        for name in _agent_path_skills(exp):
            if name not in counts:
                continue
            bucket = counts[name]
            bucket[outcome] += 1
            bucket["chain_len_sum"] += chain_len
            # Track the most recent ISO timestamp seen.
            if created_at:
                if not bucket["last_used"] or created_at > bucket["last_used"]:
                    bucket["last_used"] = created_at

    out: dict[str, SkillScore] = {}
    for name in requested:
        c = counts[name]
        s = c["success"]
        p = c["partial"]
        f = c["fail"]
        total = s + p + f
        if total == 0:
            out[name] = SkillScore(skill_name=name)
            continue

        # Win rate: partial counts half-credit.
        win_rate = (s + 0.5 * p) / total
        # Wilson uses hard successes. Partial does NOT lift confidence.
        conf = wilson_lower_bound(successes=s, total=total)
        avg_chain = c["chain_len_sum"] / total

        out[name] = SkillScore(
            skill_name=name,
            sample_size=total,
            success_count=s,
            partial_count=p,
            fail_count=f,
            win_rate=win_rate,
            confidence_lower=conf,
            avg_chain_len=avg_chain,
            last_used=c["last_used"],
            is_low_confidence=total < min_sample_for_confidence,
        )

    return out


def _ranking_score(score: SkillScore) -> float:
    """Single-number used inside `rank_skills_*` helpers.

    Low-confidence skills get penalized to 0 so they fall to priority-
    only ordering inside their tier. Above the threshold, the Wilson
    lower bound is the ranking signal — it naturally penalizes both
    losers (low rate) and cold-starters (wide interval).
    """
    if score.is_low_confidence:
        return 0.0
    return score.confidence_lower


def rank_skills_hybrid(
    skills_with_priority: list[tuple[str, int]],
    scores: dict[str, SkillScore],
) -> list[tuple[str, int]]:
    """Sort by (priority asc, ranking_score desc).

    Banking compliance: priority remains THE law. Score only orders
    within the same priority tier. A high-scoring low-priority skill
    NEVER beats a low-scoring high-priority one. This guarantees that
    a deterministic-detector skill (priority 10) always runs before a
    speculative learned skill (priority 50), no matter how good the
    learned one looks.
    """
    def sort_key(item: tuple[str, int]) -> tuple[int, float]:
        name, priority = item
        score_val = _ranking_score(scores.get(name, SkillScore(skill_name=name)))
        # Negate the score so larger comes first under ascending sort.
        return (priority, -score_val)

    return sorted(skills_with_priority, key=sort_key)


def rank_skills_score_only(
    skills_with_priority: list[tuple[str, int]],
    scores: dict[str, SkillScore],
) -> list[tuple[str, int]]:
    """Sort purely by ranking_score (descending). Priority is ignored.

    Reserved for experimentation. NOT used by the loader's `hybrid`
    mode — that one keeps priority as the primary sort.
    """
    def sort_key(item: tuple[str, int]) -> tuple[float, int]:
        name, priority = item
        score_val = _ranking_score(scores.get(name, SkillScore(skill_name=name)))
        return (-score_val, priority)

    return sorted(skills_with_priority, key=sort_key)
