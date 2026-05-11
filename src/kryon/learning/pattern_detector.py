"""Pattern detector — find recurrent chain clusters worth proposing as skills.

Runs over the experience corpus. A "cluster" is a group of engagements
where:
  * outcome ∈ {success, partial} — failures don't seed patterns
  * chain length >= 2 — single-tool chains have no signature
  * pairwise chain similarity (Jaccard on bigrams) >= threshold
  * pairwise profile similarity (tech overlap) > 0
  * cluster size >= min_repetitions

Each cluster yields a `ChainCluster` with a deterministic id, the modal
chain as its representative, and the union of member techs as profile.
The synthesizer (Fase 3.2) consumes these to draft auto-skills.

Design notes:
  * No LLM here. Pure set/Jaccard math, easy to test.
  * Union-Find (disjoint set) for clustering — `O(n² · α(n))` over the
    corpus size, dominated by the n² similarity step. For corpora <
    ~10K experiences this is fine; beyond that, swap in HDBSCAN or
    similar over an embedded representation.
  * cluster_id is sha1 over the modal chain + sorted tech list, so
    identical re-runs produce identical ids (lets the caller dedupe).
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Any

# Jaccard threshold for "same chain pattern". 0.75 = mostly same tool order.
_DEFAULT_SIMILARITY_THRESHOLD = 0.75
_MIN_REPETITIONS = 3
_MIN_CHAIN_LEN = 2

# Outcome score weights (mirror score_skills' partial-counts-half logic).
_OUTCOME_SCORE = {
    "success": 1.0,
    "partial": 0.5,
    "fail": 0.0,
    "recon-only": 0.0,
}


@dataclass(frozen=True)
class ChainCluster:
    """A cluster of experiences with similar chain + profile signatures."""

    cluster_id: str
    member_experience_ids: tuple[str, ...]
    representative_chain: tuple[str, ...]
    representative_profile: dict[str, Any]
    sample_size: int
    avg_outcome_score: float


# ---------- Similarity primitives ----------


def chain_bigrams(tools: list[str]) -> list[tuple[str, str]]:
    """Consecutive tool pairs. `[a,b,c]` → `[(a,b),(b,c)]`."""
    return [(tools[i], tools[i + 1]) for i in range(len(tools) - 1)]


def jaccard(a: set, b: set) -> float:
    """|A ∩ B| / |A ∪ B|. Returns 0 when both sets are empty."""
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def chain_similarity(chain_a: list[str], chain_b: list[str]) -> float:
    """Jaccard over chain bigrams. Captures order-aware tool patterns
    while tolerating extra/missing intermediate steps."""
    return jaccard(set(chain_bigrams(chain_a)), set(chain_bigrams(chain_b)))


def profile_similarity(profile_a: dict, profile_b: dict) -> float:
    """Jaccard over the tech token sets."""
    a = {t.lower() for t in (profile_a.get("tech") or [])}
    b = {t.lower() for t in (profile_b.get("tech") or [])}
    return jaccard(a, b)


def _combined_similarity(exp_a: dict, exp_b: dict) -> float:
    """Weighted average — chain dominates (0.7), profile gates (0.3).

    A pair with strong chain match but no shared tech can still cluster
    if the chain match is overwhelming; conversely two engagements on
    same tech but different chain don't cluster.
    """
    chain_a = [s.get("tool", "") for s in (exp_a.get("chain") or [])]
    chain_b = [s.get("tool", "") for s in (exp_b.get("chain") or [])]
    cs = chain_similarity(chain_a, chain_b)
    ps = profile_similarity(
        exp_a.get("target_profile") or {},
        exp_b.get("target_profile") or {},
    )
    # If both profiles are completely empty (rare), fall back to chain only.
    if not (exp_a.get("target_profile") or {}).get("tech") and not (exp_b.get("target_profile") or {}).get("tech"):
        return cs
    return 0.7 * cs + 0.3 * ps


# ---------- Union-find for clustering ----------


class _DSU:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1


# ---------- Cluster construction ----------


def _qualifies(exp: dict) -> bool:
    """An experience must meet outcome + chain-length thresholds to seed a cluster."""
    outcome = exp.get("outcome", "fail")
    if outcome not in ("success", "partial"):
        return False
    chain = exp.get("chain") or []
    return len(chain) >= _MIN_CHAIN_LEN


def _modal_chain(experiences: list[dict]) -> tuple[str, ...]:
    """The most common exact tool sequence among cluster members."""
    sequences = [tuple(s.get("tool", "") for s in (exp.get("chain") or [])) for exp in experiences]
    counts = Counter(sequences)
    if not counts:
        return ()
    return counts.most_common(1)[0][0]


def _union_profile(experiences: list[dict]) -> dict[str, Any]:
    """Aggregate member profiles into one — union of tech, intersect of ports."""
    techs: set[str] = set()
    ports: list[set[int]] = []
    hosts: list[str] = []
    for exp in experiences:
        prof = exp.get("target_profile") or {}
        for t in prof.get("tech") or []:
            techs.add(t)
        if prof.get("ports"):
            ports.append(set(prof["ports"]))
        if prof.get("host"):
            hosts.append(prof["host"])
    common_ports = sorted(set.intersection(*ports)) if ports else []
    return {
        "tech": sorted(techs),
        "ports": common_ports,
        "sample_hosts": hosts[:3],
    }


def _cluster_id(modal: tuple[str, ...], tech_sorted: list[str]) -> str:
    """Deterministic id from modal chain + sorted tech."""
    payload = "|".join(modal) + "::" + ",".join(tech_sorted)
    return "cluster_" + hashlib.sha1(payload.encode()).hexdigest()[:12]


def _avg_outcome(experiences: list[dict]) -> float:
    if not experiences:
        return 0.0
    total = sum(_OUTCOME_SCORE.get(e.get("outcome", "fail"), 0.0) for e in experiences)
    return total / len(experiences)


def detect_recurrent_chains(
    experiences: list[dict],
    *,
    min_repetitions: int = _MIN_REPETITIONS,
    similarity_threshold: float = _DEFAULT_SIMILARITY_THRESHOLD,
) -> list[ChainCluster]:
    """Find clusters of similar engagements worth synthesizing as skills.

    Args:
        experiences: list from the experience store (any source matching
            the chain/profile/outcome shape).
        min_repetitions: minimum cluster size to surface.
        similarity_threshold: pairwise similarity cutoff for clustering.

    Returns:
        list of ChainCluster, sorted by sample_size descending.
    """
    qualified = [e for e in experiences if _qualifies(e)]
    n = len(qualified)
    if n < min_repetitions:
        return []

    dsu = _DSU(n)
    for i in range(n):
        for j in range(i + 1, n):
            if _combined_similarity(qualified[i], qualified[j]) >= similarity_threshold:
                dsu.union(i, j)

    # Group by cluster root
    groups: dict[int, list[int]] = {}
    for i in range(n):
        root = dsu.find(i)
        groups.setdefault(root, []).append(i)

    clusters: list[ChainCluster] = []
    for indices in groups.values():
        if len(indices) < min_repetitions:
            continue
        members = [qualified[i] for i in indices]
        modal = _modal_chain(members)
        rep_profile = _union_profile(members)
        cid = _cluster_id(modal, list(rep_profile["tech"]))
        clusters.append(
            ChainCluster(
                cluster_id=cid,
                member_experience_ids=tuple(e.get("id", "") for e in members),
                representative_chain=modal,
                representative_profile=rep_profile,
                sample_size=len(members),
                avg_outcome_score=_avg_outcome(members),
            )
        )

    # Largest clusters first; ties broken by id for determinism.
    clusters.sort(key=lambda c: (-c.sample_size, c.cluster_id))
    return clusters
