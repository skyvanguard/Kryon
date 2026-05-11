"""TDD contract for kryon.learning.pattern_detector.

Pure tests — no DB, no LLM. Detects clusters of similar engagements
that justify proposing an auto-synthesized skill.

Cluster criteria:
  * chain tool-name similarity >= threshold (Jaccard on bigrams)
  * profile tech overlap (>= 1 shared tech token, OR both empty)
  * outcome ∈ {success, partial}
  * cluster size >= min_repetitions
"""

from __future__ import annotations

from typing import Any

import pytest

# ---------- Helpers ----------


def _experience(
    *,
    eid: str,
    tools: list[str],
    tech: list[str] | None = None,
    outcome: str = "success",
) -> dict[str, Any]:
    return {
        "id": eid,
        "outcome": outcome,
        "agent_path": ["recon-scout"],
        "target_profile": {
            "tech": tech if tech is not None else ["wordpress"],
            "host": f"{eid}.example.com",
            "ports": [80, 443],
        },
        "chain": [{"tool": t, "args": "", "status": "ok", "output": ""} for t in tools],
        "outcome_signals": {"shell_gained": outcome == "success"},
        "duration_s": 60,
        "created_at": "2026-04-28T17:00:00+00:00",
    }


# ---------- Similarity primitives ----------


def test_chain_bigrams_extracts_consecutive_pairs() -> None:
    from kryon.learning.pattern_detector import chain_bigrams

    assert chain_bigrams(["a", "b", "c", "d"]) == [("a", "b"), ("b", "c"), ("c", "d")]


def test_chain_bigrams_empty_chain_returns_empty() -> None:
    from kryon.learning.pattern_detector import chain_bigrams

    assert chain_bigrams([]) == []


def test_chain_bigrams_single_tool_returns_empty() -> None:
    """No bigrams from a 1-element list."""
    from kryon.learning.pattern_detector import chain_bigrams

    assert chain_bigrams(["only"]) == []


def test_jaccard_on_identical_sets_is_one() -> None:
    from kryon.learning.pattern_detector import jaccard

    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0


def test_jaccard_on_disjoint_sets_is_zero() -> None:
    from kryon.learning.pattern_detector import jaccard

    assert jaccard({"a"}, {"b"}) == 0.0


def test_jaccard_on_partial_overlap() -> None:
    from kryon.learning.pattern_detector import jaccard

    # |{a,b}∩{b,c}| / |{a,b,c}| = 1/3
    assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)


def test_jaccard_two_empty_sets_returns_zero_not_nan() -> None:
    """Empty intersection of empty sets must return 0, not divide-by-zero."""
    from kryon.learning.pattern_detector import jaccard

    assert jaccard(set(), set()) == 0.0


# ---------- Pairwise similarity ----------


def test_chain_similarity_identical_chains() -> None:
    from kryon.learning.pattern_detector import chain_similarity

    assert chain_similarity(["a", "b", "c"], ["a", "b", "c"]) == 1.0


def test_chain_similarity_completely_different() -> None:
    from kryon.learning.pattern_detector import chain_similarity

    assert chain_similarity(["a", "b"], ["x", "y"]) == 0.0


def test_chain_similarity_partial_overlap() -> None:
    """Same prefix, divergent ending."""
    from kryon.learning.pattern_detector import chain_similarity

    sim = chain_similarity(["nmap", "whatweb", "nuclei"], ["nmap", "whatweb", "gobuster"])
    assert 0.3 < sim < 1.0


def test_profile_similarity_shared_tech() -> None:
    from kryon.learning.pattern_detector import profile_similarity

    a = {"tech": ["wordpress", "php"]}
    b = {"tech": ["wordpress", "nginx"]}
    assert profile_similarity(a, b) > 0.0


def test_profile_similarity_no_shared_tech() -> None:
    from kryon.learning.pattern_detector import profile_similarity

    a = {"tech": ["wordpress"]}
    b = {"tech": ["sharepoint"]}
    assert profile_similarity(a, b) == 0.0


# ---------- Cluster detection ----------


def test_detect_returns_empty_for_empty_input() -> None:
    from kryon.learning.pattern_detector import detect_recurrent_chains

    assert detect_recurrent_chains([]) == []


def test_detect_filters_failed_outcomes() -> None:
    """`fail` and `recon-only` engagements never seed a cluster."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [_experience(eid=f"e{i}", tools=["nmap", "whatweb", "nuclei"], outcome="fail") for i in range(5)]
    assert detect_recurrent_chains(exps, min_repetitions=3) == []


def test_detect_filters_chains_with_only_one_tool() -> None:
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [_experience(eid=f"e{i}", tools=["nmap"]) for i in range(5)]
    # Single-tool chains have no bigrams → can't cluster.
    assert detect_recurrent_chains(exps, min_repetitions=3) == []


def test_detect_finds_obvious_cluster_of_three() -> None:
    """3 engagements with the same chain + same tech → 1 cluster."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["nmap", "whatweb", "nuclei"]),
        _experience(eid="e2", tools=["nmap", "whatweb", "nuclei"]),
        _experience(eid="e3", tools=["nmap", "whatweb", "nuclei"]),
    ]
    clusters = detect_recurrent_chains(exps, min_repetitions=3)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.sample_size == 3
    assert set(cluster.member_experience_ids) == {"e1", "e2", "e3"}


def test_detect_does_not_cluster_unrelated_engagements() -> None:
    """3 WP + 3 SSH brute → 2 separate clusters (each big enough)."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    wp = [
        _experience(
            eid=f"wp{i}",
            tools=["nmap", "whatweb", "nuclei"],
            tech=["wordpress"],
        )
        for i in range(3)
    ]
    ssh = [
        _experience(
            eid=f"ssh{i}",
            tools=["nmap", "hydra", "ssh"],
            tech=["openssh"],
        )
        for i in range(3)
    ]
    clusters = detect_recurrent_chains(wp + ssh, min_repetitions=3)
    assert len(clusters) == 2
    cluster_techs = {c.representative_profile.get("tech", [None])[0] for c in clusters}
    assert "wordpress" in cluster_techs
    assert "openssh" in cluster_techs


def test_detect_respects_min_repetitions() -> None:
    """A would-be cluster of 2 below threshold doesn't surface."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["nmap", "whatweb"]),
        _experience(eid="e2", tools=["nmap", "whatweb"]),
    ]
    assert detect_recurrent_chains(exps, min_repetitions=3) == []
    # But 2 is enough when explicitly relaxed.
    out = detect_recurrent_chains(exps, min_repetitions=2)
    assert len(out) == 1


def test_detect_includes_partial_outcomes() -> None:
    """Partial counts toward cluster qualification (synth accepts partials too)."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["nmap", "whatweb"], outcome="partial"),
        _experience(eid="e2", tools=["nmap", "whatweb"], outcome="success"),
        _experience(eid="e3", tools=["nmap", "whatweb"], outcome="partial"),
    ]
    clusters = detect_recurrent_chains(exps, min_repetitions=3)
    assert len(clusters) == 1
    assert clusters[0].sample_size == 3


def test_detect_avg_outcome_score_weights_partials_half() -> None:
    """Same blend logic as score_skills: success=1, partial=0.5, fail=0."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["a", "b"], outcome="success"),
        _experience(eid="e2", tools=["a", "b"], outcome="success"),
        _experience(eid="e3", tools=["a", "b"], outcome="partial"),
    ]
    clusters = detect_recurrent_chains(exps, min_repetitions=3)
    assert len(clusters) == 1
    # (1 + 1 + 0.5) / 3
    assert clusters[0].avg_outcome_score == pytest.approx(2.5 / 3)


# ---------- Representative selection ----------


def test_representative_chain_uses_most_common() -> None:
    """The cluster's representative chain is the modal sequence among members."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["nmap", "whatweb", "nuclei"]),
        _experience(eid="e2", tools=["nmap", "whatweb", "nuclei"]),
        _experience(eid="e3", tools=["nmap", "whatweb", "gobuster"]),  # variant
    ]
    clusters = detect_recurrent_chains(
        exps,
        min_repetitions=3,
        similarity_threshold=0.4,
    )
    assert len(clusters) == 1
    # Modal chain wins.
    assert clusters[0].representative_chain == ("nmap", "whatweb", "nuclei")


def test_representative_profile_aggregates_member_tech() -> None:
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["a", "b"], tech=["wordpress", "php"]),
        _experience(eid="e2", tools=["a", "b"], tech=["wordpress"]),
        _experience(eid="e3", tools=["a", "b"], tech=["wordpress", "mysql"]),
    ]
    clusters = detect_recurrent_chains(exps, min_repetitions=3)
    assert len(clusters) == 1
    rep_tech = set(clusters[0].representative_profile.get("tech", []))
    # Union of all member tech
    assert "wordpress" in rep_tech
    assert "php" in rep_tech
    assert "mysql" in rep_tech


# ---------- ChainCluster dataclass ----------


def test_chain_cluster_is_frozen() -> None:
    from dataclasses import FrozenInstanceError

    from kryon.learning.pattern_detector import ChainCluster

    c = ChainCluster(
        cluster_id="c1",
        member_experience_ids=("e1",),
        representative_chain=("a",),
        representative_profile={},
        sample_size=1,
        avg_outcome_score=1.0,
    )
    with pytest.raises(FrozenInstanceError):
        c.sample_size = 99  # type: ignore[misc]


def test_cluster_id_is_deterministic_across_runs() -> None:
    """Same input → same cluster_id, so callers can dedupe across cron runs."""
    from kryon.learning.pattern_detector import detect_recurrent_chains

    exps = [
        _experience(eid="e1", tools=["nmap", "whatweb", "nuclei"]),
        _experience(eid="e2", tools=["nmap", "whatweb", "nuclei"]),
        _experience(eid="e3", tools=["nmap", "whatweb", "nuclei"]),
    ]
    c1 = detect_recurrent_chains(exps, min_repetitions=3)[0]
    c2 = detect_recurrent_chains(exps, min_repetitions=3)[0]
    assert c1.cluster_id == c2.cluster_id
