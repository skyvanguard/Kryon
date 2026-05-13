"""F84.7 — Tests for ITR per-turn tool retrieval.

Mock embedder by name → vector pairs so the tests are deterministic
and don't touch Ollama / sentence-transformers.

Categories of coverage:
  - Pure cosine math (zero vec, identical, orthogonal)
  - Ranking determinism + descending-sort property
  - select_with_itr fallback paths (empty index, embedder raises,
    confidence too low)
  - always_include precedence over similarity ranking
  - max_tools cap honored
  - select_tools_itr in tool_budget integrates with the rest of the
    static path (forbidden filter, registry lookup)
"""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any

import pytest

from kryon.skills.itr_retriever import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_MIN_HIGH_CONFIDENCE,
    Embedder,
    ToolMatch,
    _cosine,
    rank_tools,
    select_with_itr,
)
from kryon.skills.tool_budget import ALWAYS_INCLUDE, select_tools_itr


# =====================================================================
# Pure cosine math
# =====================================================================


def test_cosine_identical_vectors_is_one():
    assert math.isclose(_cosine([1.0, 0.0, 0.0], [1.0, 0.0, 0.0]), 1.0, abs_tol=1e-9)


def test_cosine_orthogonal_vectors_is_zero():
    assert math.isclose(_cosine([1.0, 0.0], [0.0, 1.0]), 0.0, abs_tol=1e-9)


def test_cosine_zero_norm_returns_zero():
    """Zero-norm vectors would NaN with naive division; the helper
    must return 0 deterministically so the ranker doesn't propagate
    NaN through the report."""
    assert _cosine([0.0, 0.0], [1.0, 1.0]) == 0.0
    assert _cosine([1.0, 1.0], [0.0, 0.0]) == 0.0


def test_cosine_mismatched_lengths_returns_zero():
    assert _cosine([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0


# =====================================================================
# Ranking
# =====================================================================


def test_rank_tools_descending():
    """Ranking should sort by similarity highest-first; equal
    similarities preserve insertion order (stable sort)."""
    query = [1.0, 0.0]
    index = {
        "match_perfect": [1.0, 0.0],
        "match_partial": [0.7, 0.3],
        "match_orthogonal": [0.0, 1.0],
    }
    ranked = rank_tools(query, index)
    assert [m.tool_name for m in ranked][0] == "match_perfect"
    assert ranked[0].similarity > ranked[1].similarity > ranked[2].similarity


def test_rank_tools_empty_index():
    assert rank_tools([1.0, 0.0], {}) == []


def test_rank_tools_returns_tool_match_dataclass():
    ranked = rank_tools([1.0], {"a": [1.0]})
    assert isinstance(ranked[0], ToolMatch)
    assert ranked[0].tool_name == "a"


# =====================================================================
# select_with_itr fallback paths
# =====================================================================


class _StaticEmbedder:
    """Returns a fixed vector regardless of query. Use for the happy
    path where we control the cosine ranking via the index."""

    def __init__(self, vec: list[float]) -> None:
        self.vec = vec
        self.calls = 0

    def embed_query(self, text: str) -> list[float]:
        self.calls += 1
        return list(self.vec)


class _RaisingEmbedder:
    def embed_query(self, text: str) -> list[float]:
        raise RuntimeError("ollama unreachable")


class _EmptyEmbedder:
    def embed_query(self, text: str) -> list[float]:
        return []


def test_select_with_itr_empty_index_returns_none():
    result = select_with_itr(
        "find sql injection",
        _StaticEmbedder([1.0, 0.0]),
        {},
        max_tools=10,
        always_include=set(),
    )
    assert result is None


def test_select_with_itr_embedder_raises_returns_none():
    result = select_with_itr(
        "find sql injection",
        _RaisingEmbedder(),
        {"sqlmap": [1.0, 0.0]},
        max_tools=10,
        always_include=set(),
    )
    assert result is None


def test_select_with_itr_empty_query_vec_returns_none():
    result = select_with_itr(
        "x",
        _EmptyEmbedder(),
        {"sqlmap": [1.0, 0.0]},
        max_tools=10,
        always_include=set(),
    )
    assert result is None


def test_select_with_itr_too_few_hits_returns_none():
    """If fewer than min_high_confidence tools clear the threshold,
    we must signal fallback. This is the "ambiguous query" path."""
    # Only one tool above threshold (the query vector matches itself
    # perfectly; the orthogonal tool ranks at 0).
    index = {
        "match": [1.0, 0.0],
        "miss1": [0.0, 1.0],
        "miss2": [0.0, 1.0],
    }
    result = select_with_itr(
        "perfect match",
        _StaticEmbedder([1.0, 0.0]),
        index,
        max_tools=10,
        always_include=set(),
        min_high_confidence=5,  # require 5; we only have 1
    )
    assert result is None


# =====================================================================
# Happy path: ranking + threshold + always_include + cap
# =====================================================================


def _gradient_index(n: int) -> dict[str, list[float]]:
    """Build n tools whose vectors gradually drift away from [1,0]. The
    first ones rank highest against the query [1,0]; later ones fall
    below the 0.35 threshold."""
    index: dict[str, list[float]] = {}
    for i in range(n):
        # Smoothly rotate from [1,0] toward [0,1] over n steps.
        angle = (i / max(1, n - 1)) * (math.pi / 2)
        index[f"tool_{i:02d}"] = [math.cos(angle), math.sin(angle)]
    return index


def test_select_with_itr_returns_top_hits_above_threshold():
    """Among 20 tools spread across a quarter-rotation, the high-
    similarity ones (cos angle > 0.35) should make the cut."""
    index = _gradient_index(20)
    embedder = _StaticEmbedder([1.0, 0.0])
    selected = select_with_itr(
        "irrelevant — embedder ignores it",
        embedder,
        index,
        max_tools=30,
        always_include=set(),
        confidence_threshold=DEFAULT_CONFIDENCE_THRESHOLD,
        min_high_confidence=1,
    )
    assert selected is not None
    # tool_00 is exactly [1,0]; should be first.
    assert selected[0] == "tool_00"
    # Tools with similarity < 0.35 should NOT appear.
    for name in selected:
        idx = int(name.split("_")[1])
        angle = (idx / 19) * (math.pi / 2)
        assert math.cos(angle) >= DEFAULT_CONFIDENCE_THRESHOLD - 1e-9


def test_select_with_itr_respects_max_tools_cap():
    index = _gradient_index(20)
    embedder = _StaticEmbedder([1.0, 0.0])
    selected = select_with_itr(
        "q", embedder, index,
        max_tools=5,
        always_include=set(),
        min_high_confidence=1,
    )
    assert selected is not None
    assert len(selected) == 5


def test_select_with_itr_always_include_jumps_queue():
    """ALWAYS_INCLUDE tools must appear in the output even when their
    similarity is below the threshold (they may not appear in the
    similarity list at all, but they're still in the index)."""
    index = _gradient_index(10)
    index["run_command"] = [0.0, 1.0]  # orthogonal — would NOT clear threshold
    embedder = _StaticEmbedder([1.0, 0.0])
    selected = select_with_itr(
        "q", embedder, index,
        max_tools=10,
        always_include={"run_command"},
        min_high_confidence=1,
    )
    assert selected is not None
    assert "run_command" in selected


def test_select_with_itr_always_include_missing_from_index_is_silent():
    """If an ALWAYS_INCLUDE name isn't in the index, the retriever
    should not crash — it just can't surface that one. (The caller
    wires the registry; the index might lag during a rebuild.)"""
    index = _gradient_index(10)
    embedder = _StaticEmbedder([1.0, 0.0])
    selected = select_with_itr(
        "q", embedder, index,
        max_tools=10,
        always_include={"some_tool_not_in_index"},
        min_high_confidence=1,
    )
    assert selected is not None
    assert "some_tool_not_in_index" not in selected


# =====================================================================
# select_tools_itr integration (tool_budget.py)
# =====================================================================


def _fake_registry(names: list[str]) -> dict[str, object]:
    return {n: SimpleNamespace(name=n) for n in names}


def test_select_tools_itr_returns_none_on_empty_query():
    registry = _fake_registry(list(ALWAYS_INCLUDE) + ["sqlmap"])
    result = select_tools_itr(
        registry,
        user_query="",
        embedder=_StaticEmbedder([1.0]),
        index={"sqlmap": [1.0]},
    )
    assert result is None


def test_select_tools_itr_returns_none_on_empty_registry():
    result = select_tools_itr(
        {},
        user_query="find sql injection",
        embedder=_StaticEmbedder([1.0]),
        index={"sqlmap": [1.0]},
    )
    assert result is None


def test_select_tools_itr_resolves_registry_objects():
    """The retriever returns NAMES; the caller (select_tools_itr)
    must map them back to the registry objects with .name set."""
    names = list(ALWAYS_INCLUDE) + [f"tool_{i:02d}" for i in range(10)]
    registry = _fake_registry(names)
    embedder = _StaticEmbedder([1.0, 0.0])
    index = _gradient_index(10)
    # Add always-include vectors so they appear in the index too.
    for n in ALWAYS_INCLUDE:
        index[n] = [1.0, 0.0]
    result = select_tools_itr(
        registry,
        user_query="audit web app",
        embedder=embedder,
        index=index,
    )
    assert result is not None
    assert all(hasattr(t, "name") for t in result)
    # ALWAYS_INCLUDE present
    result_names = {t.name for t in result}
    assert "run_command" in result_names


def test_select_tools_itr_respects_forbidden_filter():
    """Same contract as select_tools: forbidden_tool_names wins."""
    names = list(ALWAYS_INCLUDE) + ["sqlmap"]
    registry = _fake_registry(names)
    embedder = _StaticEmbedder([1.0, 0.0])
    index = {n: [1.0, 0.0] for n in names}
    result = select_tools_itr(
        registry,
        user_query="audit web app",
        embedder=embedder,
        index=index,
        forbidden_tool_names={"run_command"},
    )
    assert result is not None
    assert "run_command" not in {t.name for t in result}


def test_select_tools_itr_returns_none_when_retriever_falls_back():
    """If select_with_itr returns None (e.g. embedder raised), the
    caller must propagate None to its caller — never silently
    produce an empty-or-degraded tool list."""
    registry = _fake_registry(["sqlmap"])
    result = select_tools_itr(
        registry,
        user_query="audit web app",
        embedder=_RaisingEmbedder(),
        index={"sqlmap": [1.0]},
    )
    assert result is None
