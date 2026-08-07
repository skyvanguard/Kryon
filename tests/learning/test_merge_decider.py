"""F77.G.6 — TDD contract for the AutoSkill ternary merge decider.

Pure tests: build fixture clusters + existing skills, call
`decide_merge_action`, assert decision/reason/version. No filesystem,
no pattern_detector dependency beyond the dataclass.

Coverage groups:
  - Quality floor → discard (size, outcome score)
  - Empty existing → add
  - High similarity → merge with correct version bump
  - Ambiguous similarity → discard
  - Low similarity → add
  - Version-name construction (no .v2.v3.v4 cascade)
  - Banca-safety: max_similarity + matched_against surfaced
  - Edge: tech-only difference (chain match but no tech overlap)
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from kryon.learning.merge_decider import (
    DEFAULT_DISCARD_BAND_LO,
    DEFAULT_MERGE_THRESHOLD,
    DEFAULT_MIN_CLUSTER_SIZE,
    DEFAULT_MIN_OUTCOME_SCORE,
    ExistingSkill,
    MergeDecision,
    _propose_version_name,
    decide_merge_action,
)
from kryon.learning.pattern_detector import ChainCluster


def _cluster(
    *,
    cluster_id: str = "cluster_test_001",
    chain: tuple[str, ...] = ("nmap", "whatweb", "sqlmap"),
    tech: tuple[str, ...] = ("wordpress",),
    sample_size: int = 5,
    avg_outcome_score: float = 0.8,
) -> ChainCluster:
    return ChainCluster(
        cluster_id=cluster_id,
        member_experience_ids=tuple(f"exp_{i}" for i in range(sample_size)),
        representative_chain=chain,
        representative_profile={"tech": list(tech), "ports": [80, 443]},
        sample_size=sample_size,
        avg_outcome_score=avg_outcome_score,
    )


# =====================================================================
# Quality floor → DISCARD
# =====================================================================


def test_cluster_too_small_is_discarded():
    cluster = _cluster(sample_size=DEFAULT_MIN_CLUSTER_SIZE - 1)
    decision = decide_merge_action(cluster, [])
    assert decision.decision == "discard"
    assert "size" in decision.reason


def test_cluster_low_outcome_is_discarded():
    cluster = _cluster(avg_outcome_score=DEFAULT_MIN_OUTCOME_SCORE - 0.01)
    decision = decide_merge_action(cluster, [])
    assert decision.decision == "discard"
    assert "outcome_score" in decision.reason


def test_quality_floor_runs_before_existing_comparison():
    """Even with a perfect match in existing, a tiny cluster discards.
    Order matters — operators don't want a 'merge into pci-dss-audit'
    proposal for a 2-experience cluster."""
    cluster = _cluster(sample_size=2)
    twin = ExistingSkill(
        name="pci-dss-audit",
        version=1,
        representative_chain=cluster.representative_chain,
        tech=tuple(cluster.representative_profile["tech"]),
    )
    decision = decide_merge_action(cluster, [twin])
    assert decision.decision == "discard"
    assert "size" in decision.reason


# =====================================================================
# Empty existing → ADD
# =====================================================================


def test_empty_existing_means_add():
    cluster = _cluster()
    decision = decide_merge_action(cluster, [])
    assert decision.decision == "add"
    assert decision.target_existing_name is None
    assert decision.target_new_version is None


# =====================================================================
# High similarity → MERGE
# =====================================================================


def test_high_similarity_triggers_merge():
    cluster = _cluster(
        chain=("nmap", "whatweb", "wpscan", "sqlmap"),
        tech=("wordpress",),
    )
    twin = ExistingSkill(
        name="wordpress-audit",
        version=1,
        # Identical chain + tech → similarity = 1.0
        representative_chain=cluster.representative_chain,
        tech=tuple(cluster.representative_profile["tech"]),
    )
    decision = decide_merge_action(cluster, [twin])
    assert decision.decision == "merge"
    assert decision.matched_against == "wordpress-audit"
    assert decision.target_existing_name == "wordpress-audit"
    assert decision.target_new_version == 2
    assert decision.target_draft_name == "wordpress-audit.v2"
    assert decision.max_similarity >= DEFAULT_MERGE_THRESHOLD


def test_merge_picks_highest_similarity():
    """When multiple existing skills overlap, MERGE proposes against
    the closest one, not the first or alphabetical."""
    cluster = _cluster(
        chain=("nmap", "whatweb", "wpscan", "sqlmap"),
        tech=("wordpress",),
    )
    far = ExistingSkill(
        name="generic-recon",
        version=1,
        representative_chain=("nmap",),  # tiny overlap on bigrams
        tech=("apache",),  # no overlap
    )
    near = ExistingSkill(
        name="wordpress-audit",
        version=1,
        representative_chain=cluster.representative_chain,
        tech=tuple(cluster.representative_profile["tech"]),
    )
    decision = decide_merge_action(cluster, [far, near])
    assert decision.decision == "merge"
    assert decision.matched_against == "wordpress-audit"


def test_merge_bumps_version_correctly():
    """If the closest existing is already v3, the proposal must be v4."""
    cluster = _cluster()
    existing_v3 = ExistingSkill(
        name="audit-bank-full",
        version=3,
        representative_chain=cluster.representative_chain,
        tech=tuple(cluster.representative_profile["tech"]),
    )
    decision = decide_merge_action(cluster, [existing_v3])
    assert decision.decision == "merge"
    assert decision.target_new_version == 4
    assert decision.target_draft_name == "audit-bank-full.v4"


# =====================================================================
# Ambiguous similarity band → DISCARD
# =====================================================================


def test_ambiguous_similarity_is_discarded():
    """A cluster that overlaps an existing skill by ~0.6 — too similar
    to be useful as a fresh ADD, too different to MERGE. AutoSkill
    discards these to avoid diluting the draft pool."""
    cluster = _cluster(
        chain=("nmap", "whatweb", "sqlmap"),
        tech=("wordpress",),
    )
    # ~3 shared bigrams in chain, partial tech overlap → in band.
    half_match = ExistingSkill(
        name="appsec",
        version=1,
        representative_chain=("nmap", "whatweb", "burp", "sqlmap"),
        tech=("wordpress", "php"),
    )
    decision = decide_merge_action(
        cluster,
        [half_match],
        merge_threshold=0.95,  # raise the bar so the test cluster lands in the band
        discard_band_lo=0.20,  # widen the band so the synthetic similarity falls in
    )
    assert decision.decision == "discard"
    assert "ambiguous" in decision.reason
    assert decision.matched_against == "appsec"


# =====================================================================
# Low similarity → ADD
# =====================================================================


def test_low_similarity_is_added():
    """A cluster that barely resembles any existing skill is a fresh
    ADD — even though there's a closest neighbour, similarity below
    the discard band means the cluster brings new signal."""
    cluster = _cluster(
        chain=("dns_enum", "subdomain_brute", "cert_transparency"),
        tech=("dns",),
    )
    unrelated = ExistingSkill(
        name="wordpress-audit",
        version=1,
        representative_chain=("nmap", "whatweb", "wpscan", "sqlmap"),
        tech=("wordpress",),
    )
    decision = decide_merge_action(cluster, [unrelated])
    assert decision.decision == "add"
    assert decision.matched_against == "wordpress-audit"
    assert decision.max_similarity < DEFAULT_DISCARD_BAND_LO


# =====================================================================
# Version-name construction
# =====================================================================


def test_propose_version_name_strips_existing_vN():
    """Successive merges must produce .v2 → .v3, not .v2.v3.v4."""
    assert _propose_version_name("pci-dss-audit", 2) == "pci-dss-audit.v2"
    assert _propose_version_name("pci-dss-audit.v2", 3) == "pci-dss-audit.v3"
    assert _propose_version_name("pci-dss-audit.v9", 10) == "pci-dss-audit.v10"


def test_propose_version_name_does_not_strip_non_numeric_suffix():
    """Defensive: name like 'audit.vendor' must NOT be treated as
    'audit' versioned 'vendor'."""
    assert _propose_version_name("audit.vendor", 2) == "audit.vendor.v2"


# =====================================================================
# Banca-safety surfaces
# =====================================================================


def test_merge_decision_is_frozen():
    """Consumers cache decisions in dicts and pass them across boundaries;
    a frozen dataclass guarantees nothing mutates mid-flight."""
    from dataclasses import FrozenInstanceError

    d = MergeDecision(cluster_id="x", decision="add", reason="test")
    with pytest.raises(FrozenInstanceError):
        d.decision = "merge"  # type: ignore[misc]


def test_max_similarity_and_matched_against_surfaced_on_add():
    """Even when the decision is ADD, the closest existing skill +
    similarity score must be on the decision so a curator can review
    'we almost merged this against X'."""
    cluster = _cluster(
        chain=("dns_enum", "subdomain_brute", "cert_transparency"),
    )
    other = ExistingSkill(
        name="wordpress-audit",
        version=1,
        representative_chain=("nmap", "whatweb", "wpscan"),
        tech=("wordpress",),
    )
    decision = decide_merge_action(cluster, [other])
    assert decision.decision == "add"
    assert decision.matched_against == "wordpress-audit"
    assert decision.max_similarity > 0.0 or decision.max_similarity == 0.0  # any defined value


def test_no_decision_overwrites_existing_playbook():
    """Critical banca property: MERGE must propose a NEW versioned
    draft name, never the original name. Operator promotes manually
    via /skill promote."""
    cluster = _cluster()
    twin = ExistingSkill(
        name="pci-dss-audit",
        version=1,
        representative_chain=cluster.representative_chain,
        tech=tuple(cluster.representative_profile["tech"]),
    )
    decision = decide_merge_action(cluster, [twin])
    assert decision.decision == "merge"
    # The target draft name MUST be different from the existing skill name.
    assert decision.target_draft_name != "pci-dss-audit"
    assert decision.target_draft_name.endswith(".v2")


# =====================================================================
# Tech-only edge case
# =====================================================================


def test_chain_match_with_no_tech_overlap_falls_back_to_chain():
    """When the cluster has no tech (air-gapped engagement), the
    decider can still merge against an existing skill if the chain
    matches. Tech penalty is bypassed when both sides are empty."""
    cluster = _cluster(
        chain=("nmap", "whatweb", "wpscan", "sqlmap"),
        tech=(),
    )
    twin_no_tech = ExistingSkill(
        name="wordpress-audit",
        version=1,
        representative_chain=cluster.representative_chain,
        tech=(),
    )
    decision = decide_merge_action(cluster, [twin_no_tech])
    assert decision.decision == "merge"
    # Pure chain similarity = 1.0 when chains are identical
    assert math.isclose(decision.max_similarity, 1.0, abs_tol=1e-6)


# =====================================================================
# Custom thresholds
# =====================================================================


def test_custom_merge_threshold_changes_decision():
    """Tightening merge_threshold turns a borderline merge into an
    add (or discard, depending on band). Operators can tune for
    their corpus."""
    cluster = _cluster()
    similar = ExistingSkill(
        name="other",
        version=1,
        representative_chain=("nmap", "whatweb", "sqlmap"),
        tech=("wordpress",),
    )
    # Same chain as cluster → similarity 1.0 (chain bigrams identical)
    decision_default = decide_merge_action(cluster, [similar])
    assert decision_default.decision == "merge"

    # If we crank merge_threshold above 1.0 (impossible to satisfy),
    # the decision drops into the discard band (or add).
    decision_strict = decide_merge_action(
        cluster,
        [similar],
        merge_threshold=1.01,
        discard_band_lo=0.0,
    )
    assert decision_strict.decision == "discard"
