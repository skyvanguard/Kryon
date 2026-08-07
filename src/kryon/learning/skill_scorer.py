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
    """One skill's aggregate performance over the experience corpus.

    F77.G.5 (SAGE dual-reward, arxiv 2512.17102) adds the `reusability_*`
    + `combined_score` fields. They default to 0 so callers that don't
    pass telemetry get exactly the legacy F2 Wilson-only behaviour.
    """

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
    # F77.G.5 — second reward axis. Counts how many *distinct* selection
    # log records (i.e. independent engagements / turns) selected the
    # skill. Normalized against the corpus max into [0, 1]. The
    # `combined_score` is the weighted blend used by rank_skills_dual.
    reusability_count: int = 0
    reusability_norm: float = 0.0
    combined_score: float = 0.0


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


# F77.G.5 — weight applied to Wilson lower bound in the combined score.
# 0.7 means Wilson dominates the ranking decision; reusability nudges
# tie-breaks. We picked 0.7 over 0.5 because correctness > popularity
# for banking compliance: a skill the operator happens to invoke a lot
# but that fails 40% of the time should NOT outrank a quieter skill
# with a tight Wilson interval.
_DEFAULT_WILSON_WEIGHT = 0.7
_DEFAULT_REUSE_WEIGHT = 0.3


def reusability_from_telemetry(
    telemetry_records: list[dict[str, Any]],
    skill_names: list[str],
) -> dict[str, int]:
    """Count how many distinct selection-log records selected each
    skill. One log record = one turn; selecting the same skill twice
    in one turn (impossible today but defensive) counts once.

    Args:
        telemetry_records: rows from selection_telemetry.read_recent()
            or any source matching that shape — each must carry a
            `selected: list[str]` field.
        skill_names: skills to score. Unrequested names are dropped
            from the returned dict so the caller never has to filter.

    Returns:
        dict[skill_name -> count]. Skills present in `skill_names` but
        absent from every log record return 0.
    """
    requested = set(skill_names)
    counts: dict[str, int] = dict.fromkeys(requested, 0)
    for record in telemetry_records:
        selected = record.get("selected") or []
        if not isinstance(selected, list):
            continue
        # dedupe within a single record so a (defensive) duplicate
        # entry doesn't double-count.
        for name in set(selected):
            if name in counts:
                counts[name] += 1
    return counts


def _normalize_counts(counts: dict[str, int]) -> dict[str, float]:
    """Map raw counts to [0, 1] by dividing by the corpus max.

    Empty corpus / all-zero counts return all-zero norms so the
    combined score reduces to Wilson * w_wilson.
    """
    if not counts:
        return {}
    max_count = max(counts.values(), default=0)
    if max_count <= 0:
        return dict.fromkeys(counts, 0.0)
    return {name: c / max_count for name, c in counts.items()}


def score_skills(
    experiences: list[dict[str, Any]],
    skill_names: list[str],
    *,
    min_sample_for_confidence: int = _DEFAULT_MIN_SAMPLE,
    telemetry_records: list[dict[str, Any]] | None = None,
    wilson_weight: float = _DEFAULT_WILSON_WEIGHT,
    reuse_weight: float = _DEFAULT_REUSE_WEIGHT,
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

    # F77.G.5 — reusability axis. None telemetry → all-zero counts so
    # combined_score collapses to wilson * wilson_weight.
    reuse_counts: dict[str, int]
    if telemetry_records is None:
        reuse_counts = dict.fromkeys(requested, 0)
    else:
        reuse_counts = reusability_from_telemetry(telemetry_records, list(requested))
    reuse_norms = _normalize_counts(reuse_counts)

    out: dict[str, SkillScore] = {}
    for name in requested:
        c = counts[name]
        s = c["success"]
        p = c["partial"]
        f = c["fail"]
        total = s + p + f
        reuse_count = reuse_counts.get(name, 0)
        reuse_norm = reuse_norms.get(name, 0.0)
        if total == 0:
            # Cold-start skill: surface the reusability signal but zero
            # everything correctness-derived. Wilson is 0 so combined
            # is just reuse_weight * reuse_norm — still useful for the
            # leaderboard "noticed but never validated" bucket.
            combined = reuse_weight * reuse_norm
            out[name] = SkillScore(
                skill_name=name,
                reusability_count=reuse_count,
                reusability_norm=reuse_norm,
                combined_score=combined,
            )
            continue

        # Win rate: partial counts half-credit.
        win_rate = (s + 0.5 * p) / total
        # Wilson uses hard successes. Partial does NOT lift confidence.
        conf = wilson_lower_bound(successes=s, total=total)
        avg_chain = c["chain_len_sum"] / total

        # Low-confidence skills do NOT contribute Wilson to the combined
        # score — same rule as _ranking_score for the legacy hybrid path.
        is_low_conf = total < min_sample_for_confidence
        effective_wilson = 0.0 if is_low_conf else conf
        combined = wilson_weight * effective_wilson + reuse_weight * reuse_norm

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
            is_low_confidence=is_low_conf,
            reusability_count=reuse_count,
            reusability_norm=reuse_norm,
            combined_score=combined,
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


def _dual_score(score: SkillScore) -> float:
    """Single-number ranker for the dual-reward path. Same low-confidence
    rule as `_ranking_score`: skills with too few samples contribute
    only their reusability share to the score, never their Wilson
    component (because the interval is too wide to trust).

    The `combined_score` field is already populated with the correct
    blend, but we recompute the post-low-confidence-floor value here
    so it's obvious in the ranker exactly what's being sorted.
    """
    return score.combined_score


def rank_skills_dual(
    skills_with_priority: list[tuple[str, int]],
    scores: dict[str, SkillScore],
) -> list[tuple[str, int]]:
    """F77.G.5 (SAGE dual-reward) — sort by (priority asc, combined_score
    desc). Same banking-safety contract as `rank_skills_hybrid`:
    priority is THE primary law, the score (now blending Wilson +
    reusability) only orders within a tier. A high-reuse low-priority
    skill NEVER beats a low-reuse high-priority one.
    """

    def sort_key(item: tuple[str, int]) -> tuple[int, float]:
        name, priority = item
        score_val = _dual_score(scores.get(name, SkillScore(skill_name=name)))
        return (priority, -score_val)

    return sorted(skills_with_priority, key=sort_key)
