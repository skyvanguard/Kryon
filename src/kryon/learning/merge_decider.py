"""F77.G.6 — AutoSkill ternary merge decider.

Implements the {add | merge | discard} decision pattern from AutoSkill
(arxiv 2603.01145, ECNU-ICALK/AutoSkill) over the output of
`kryon.learning.pattern_detector`.

Why this matters:
  - F77.G F3 (`auto_pipeline`) already clusters experiences and would
    happily synthesize a fresh draft for every cluster. On a real
    deployment that means the operator opens `~/.kryon/drafts/` and
    finds three different `auto_web_pentest_*.md` files describing
    overlapping chains — annoying at best, misleading at worst.
  - The fix is a triage step BEFORE synthesis: for each cluster,
    compare it against the existing draft pool + the promoted
    playbooks and decide:

        ADD     — cluster is semantically new; synthesize a fresh draft.
        MERGE   — cluster overlaps an existing skill enough that the
                  honest action is to propose a versioned v2 of that
                  skill (e.g. `pci-dss-audit.v2.md`), carrying the new
                  cluster as additional evidence. Operator promotes
                  manually.
        DISCARD — cluster is degenerate (too small, low outcome score,
                  or sits in the ambiguous similarity band) — skip it
                  silently rather than dilute the draft pool.

Banking-safety:
  - MERGE never overwrites an existing skill in `playbooks/`. It
    proposes a NEW `.vN.md` draft in `~/.kryon/drafts/`. The operator
    inspects, runs the existing tests, and promotes if (and only if)
    the v2 supersedes v1.
  - DISCARD is silent by design — but the decider returns the full
    reason chain so a curator can audit the corpus with
    `/skill auto detect --explain`.

Inputs:
  - One `ChainCluster` from `pattern_detector.detect_recurrent_chains`.
  - A list of `ExistingSkill` (name + version + signature) that
    represents both promoted skills and drafts already on disk.

Outputs:
  - A `MergeDecision` (frozen dataclass) capturing the action, the
    matched existing skill if any, the proposed version, the
    similarity score, and a human-readable reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from kryon.learning.pattern_detector import (
    ChainCluster,
    chain_similarity,
    jaccard,
)

__all__ = [
    "ExistingSkill",
    "MergeDecision",
    "decide_merge_action",
    "DEFAULT_MERGE_THRESHOLD",
    "DEFAULT_DISCARD_BAND_LO",
    "DEFAULT_DISCARD_BAND_HI",
    "DEFAULT_MIN_CLUSTER_SIZE",
    "DEFAULT_MIN_OUTCOME_SCORE",
]


# F77.G.6 — Similarity thresholds. Tuned to the same 0.7/0.3 weighting
# that pattern_detector._combined_similarity uses, so the numbers are
# comparable across both modules.
#
# combined_similarity >= MERGE_THRESHOLD          → MERGE
# DISCARD_BAND_LO <= combined < DISCARD_BAND_HI   → DISCARD
# combined < DISCARD_BAND_LO                      → ADD
DEFAULT_MERGE_THRESHOLD = 0.80
DEFAULT_DISCARD_BAND_LO = 0.50
DEFAULT_DISCARD_BAND_HI = DEFAULT_MERGE_THRESHOLD

# A cluster must clear these floors to be eligible for ADD/MERGE.
# Anything below them is DISCARD regardless of similarity.
DEFAULT_MIN_CLUSTER_SIZE = 3
DEFAULT_MIN_OUTCOME_SCORE = 0.4


Decision = Literal["add", "merge", "discard"]


@dataclass(frozen=True)
class ExistingSkill:
    """One skill the decider compares against. Built by the caller from
    both promoted playbooks and pending drafts so the decider doesn't
    care about either filesystem layout."""

    name: str
    version: int  # 1 when no .vN suffix
    representative_chain: tuple[str, ...]
    tech: tuple[str, ...]


@dataclass(frozen=True)
class MergeDecision:
    """The decider's verdict on one cluster. Always populated; consumers
    branch on `.decision` to know which fields to read."""

    cluster_id: str
    decision: Decision
    reason: str
    max_similarity: float = 0.0
    matched_against: str | None = None
    # MERGE only. None on add/discard.
    target_existing_name: str | None = None
    target_new_version: int | None = None
    target_draft_name: str | None = None  # e.g. "pci-dss-audit.v2"


def _combined_similarity(
    cluster_chain: tuple[str, ...],
    cluster_tech: tuple[str, ...],
    other_chain: tuple[str, ...],
    other_tech: tuple[str, ...],
) -> float:
    """Match pattern_detector's 0.7 chain + 0.3 profile weighting.

    Returns chain-only when both tech sets are empty (e.g. a cluster
    detected from an air-gapped engagement with no fingerprinting),
    falling back gracefully to chain similarity alone."""
    cs = chain_similarity(list(cluster_chain), list(other_chain))
    if not cluster_tech and not other_tech:
        return cs
    ps = jaccard({t.lower() for t in cluster_tech}, {t.lower() for t in other_tech})
    return 0.7 * cs + 0.3 * ps


def _propose_version_name(base_name: str, version: int) -> str:
    """Construct the draft slug for a versioned merge proposal.

    Naming convention: <base>.v<N>. The base is the existing skill's
    name with any trailing .vK stripped, so successive merges produce
    .v2, .v3, ... not .v2.v3.v4.
    """
    stem = base_name
    # Defensive: trim trailing .vK if a caller passes a versioned name.
    parts = stem.rsplit(".v", 1)
    if len(parts) == 2 and parts[1].isdigit():
        stem = parts[0]
    return f"{stem}.v{version}"


def decide_merge_action(
    cluster: ChainCluster,
    existing: list[ExistingSkill],
    *,
    merge_threshold: float = DEFAULT_MERGE_THRESHOLD,
    discard_band_lo: float = DEFAULT_DISCARD_BAND_LO,
    discard_band_hi: float | None = None,
    min_cluster_size: int = DEFAULT_MIN_CLUSTER_SIZE,
    min_outcome_score: float = DEFAULT_MIN_OUTCOME_SCORE,
) -> MergeDecision:
    """AutoSkill ternary triage on one cluster.

    Decision tree (in this exact order):
      1. Cluster fails quality floor (size < min_cluster_size OR
         avg_outcome_score < min_outcome_score) → DISCARD.
      2. No existing skills to compare against → ADD.
      3. max similarity ≥ merge_threshold → MERGE against argmax.
      4. discard_band_lo ≤ max similarity < discard_band_hi → DISCARD.
      5. Otherwise (max similarity < discard_band_lo) → ADD.

    `discard_band_hi` defaults to `merge_threshold` so the bands are
    contiguous. Callers that want a gap between MERGE and DISCARD can
    pass an explicit value.
    """
    if discard_band_hi is None:
        discard_band_hi = merge_threshold

    # 1. Quality floor.
    if cluster.sample_size < min_cluster_size:
        return MergeDecision(
            cluster_id=cluster.cluster_id,
            decision="discard",
            reason=(
                f"cluster size {cluster.sample_size} < min_cluster_size "
                f"{min_cluster_size}"
            ),
        )
    if cluster.avg_outcome_score < min_outcome_score:
        return MergeDecision(
            cluster_id=cluster.cluster_id,
            decision="discard",
            reason=(
                f"avg_outcome_score {cluster.avg_outcome_score:.2f} < "
                f"min_outcome_score {min_outcome_score:.2f}"
            ),
        )

    # 2. Empty existing — every new cluster is a fresh ADD.
    if not existing:
        return MergeDecision(
            cluster_id=cluster.cluster_id,
            decision="add",
            reason="no existing skills to compare against",
        )

    cluster_tech = tuple(cluster.representative_profile.get("tech") or ())

    # Find the closest existing skill. Use is-None bootstrap so a
    # cluster with similarity 0 against every candidate still records
    # the closest one (alphabetical wins on ties) — this lets the
    # curator see what the agent compared against even on an ADD.
    best: ExistingSkill | None = None
    best_sim = -1.0
    for ex in existing:
        sim = _combined_similarity(
            cluster.representative_chain,
            cluster_tech,
            ex.representative_chain,
            ex.tech,
        )
        if best is None or sim > best_sim:
            best_sim = sim
            best = ex

    # Normalize a non-set best_sim to 0 so the decision surfaces a
    # well-defined number (similarity floor, not -1).
    if best_sim < 0:
        best_sim = 0.0

    if best is None:
        # Defensive: `existing` was checked non-empty above, but a future
        # refactor that filters mid-loop might land here.
        return MergeDecision(
            cluster_id=cluster.cluster_id,
            decision="add",
            reason="no comparable existing skill",
        )

    # 3. MERGE band.
    if best_sim >= merge_threshold:
        new_version = best.version + 1
        proposed_name = _propose_version_name(best.name, new_version)
        return MergeDecision(
            cluster_id=cluster.cluster_id,
            decision="merge",
            reason=(
                f"similarity {best_sim:.2f} >= merge_threshold "
                f"{merge_threshold:.2f} against {best.name} (v{best.version})"
            ),
            max_similarity=best_sim,
            matched_against=best.name,
            target_existing_name=best.name,
            target_new_version=new_version,
            target_draft_name=proposed_name,
        )

    # 4. Ambiguous band — overlapping but not enough to merge. AutoSkill
    # discards these to avoid diluting the draft pool with near-dupes
    # that don't bring new signal.
    if discard_band_lo <= best_sim < discard_band_hi:
        return MergeDecision(
            cluster_id=cluster.cluster_id,
            decision="discard",
            reason=(
                f"ambiguous similarity {best_sim:.2f} in band "
                f"[{discard_band_lo:.2f}, {discard_band_hi:.2f}) "
                f"against {best.name}"
            ),
            max_similarity=best_sim,
            matched_against=best.name,
        )

    # 5. ADD — semantically new pattern.
    return MergeDecision(
        cluster_id=cluster.cluster_id,
        decision="add",
        reason=(
            f"max similarity {best_sim:.2f} < discard_band_lo "
            f"{discard_band_lo:.2f}; closest neighbour was {best.name}"
        ),
        max_similarity=best_sim,
        matched_against=best.name,
    )
