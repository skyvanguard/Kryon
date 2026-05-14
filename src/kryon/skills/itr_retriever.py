"""F84.7 — Instruction-Tool Retrieval (ITR) per-turn tool selector.

Adapts the ITR pattern from arxiv 2602.17046 ("Retrieve & Re-think:
Token-efficient Tool Retrieval for LLM Agents") + the adaptive cutoff
heuristic from CAR (arxiv 2511.14769) to Kryon's tool budget problem.

The static budget in `tool_budget.select_tools` registers up to 30
tools per skill — fine for narrowly-scoped engagements but a hard
ceiling on the catalog. With ITR, we score tools against the user's
*per-turn* query and surface only the ones the embedding model agrees
are relevant. This lets the registry grow past 200 tools without
inflating the schema-tokens cost per turn (the largest contributor
to context-window pressure on `kryon-14b`'s 32K window).

Banking-safe contract:
  - Default OFF. The agent uses static selection unless
    KRYON_TOOL_BUDGET=itr is set.
  - Any retrieval failure (missing index, embedding service down,
    confidence too low) MUST return None so the caller can fall back
    cleanly to static selection. We never silently degrade to an
    empty tool list.
  - No network I/O in this module — embeddings are pulled from a
    pluggable Embedder protocol that the caller wires up. The default
    Ollama embedder lives in `itr_tool_index.py` so its dependency
    can be skipped on systems without Ollama.

Algorithm (per-turn):
  1. Embed the user query (one call to the embedder).
  2. Cosine similarity against every tool's pre-computed doc vector.
  3. Sort descending by similarity.
  4. Cut at the confidence threshold (CAR-style adaptive K): keep
     every tool whose similarity ≥ threshold, capped at max_tools.
  5. If fewer than `min_high_conf` survive, return None — caller
     interprets this as "the query is ambiguous, fall back to static".

The point estimate similarities are surfaced on `ToolMatch` so the
caller can log / trace why a tool ranked where it did.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)


__all__ = [
    "Embedder",
    "ToolMatch",
    "ToolIndex",
    "rank_tools",
    "select_with_itr",
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "DEFAULT_MIN_HIGH_CONFIDENCE",
]


# CAR paper picks a threshold around 0.30–0.40 depending on the
# embedder. nomic-embed-text v1.5 produces broadly distributed
# similarities so we pick 0.35 — empirically catches the relevant
# tools without flooding with weak hits.
DEFAULT_CONFIDENCE_THRESHOLD = 0.35
# Below this many high-confidence hits, the caller should fall back.
# Five tools is enough to seed a non-trivial engagement; anything
# less is a sign the embedder didn't recognize what the user wanted.
DEFAULT_MIN_HIGH_CONFIDENCE = 5


class Embedder(Protocol):
    """Embed a single query string into a vector. The vector format
    is a sequence of floats; we don't constrain dimensionality so an
    operator can swap nomic-embed-text for BGE / E5 without code
    changes.

    Concrete implementations must raise on failure — silent failures
    (returning zero vectors, returning None) would corrupt the
    similarity ranking and the caller couldn't tell."""

    def embed_query(self, text: str) -> list[float]: ...


@dataclass(frozen=True)
class ToolMatch:
    """A scored candidate tool. Surfaced in logs + telemetry."""

    tool_name: str
    similarity: float


# A ToolIndex is just a name->vector mapping. We keep it abstract so
# the retriever doesn't care whether the backing store is numpy npz,
# pure Python lists, or something else.
ToolIndex = dict[str, list[float]]


def _cosine(a: list[float], b: list[float]) -> float:
    """Plain-Python cosine. We avoid numpy here so the retriever
    works in environments where the optional numpy dep is missing
    (unlikely in production, but the test suite exercises this path).

    Returns 0.0 for zero-norm vectors instead of NaN — a degraded but
    well-defined score so the ranking step never crashes."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a <= 0 or norm_b <= 0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


def rank_tools(query_vec: list[float], index: ToolIndex) -> list[ToolMatch]:
    """Cosine-rank every tool in `index` against `query_vec`. Returns
    a list sorted descending by similarity. Pure function — no I/O,
    no side effects, deterministic given identical inputs.

    Empty `index` returns []. Empty `query_vec` returns matches with
    similarity 0 (the cosine helper returns 0 for malformed inputs)
    so the caller's fallback path still kicks in via the
    `min_high_confidence` check."""
    matches = [ToolMatch(tool_name=name, similarity=_cosine(query_vec, vec)) for name, vec in index.items()]
    matches.sort(key=lambda m: m.similarity, reverse=True)
    return matches


def select_with_itr(
    query: str,
    embedder: Embedder,
    index: ToolIndex,
    *,
    max_tools: int,
    always_include: set[str],
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    min_high_confidence: int = DEFAULT_MIN_HIGH_CONFIDENCE,
) -> list[str] | None:
    """Per-turn tool selection. Returns a list of tool NAMES (caller
    resolves them through the registry) or None to signal fallback.

    Inputs:
      query                  — the user message for this turn.
      embedder               — concrete Embedder. Caller wires Ollama
                               / sentence-transformers / mock.
      index                  — pre-built ToolIndex (typically from
                               itr_tool_index.load_index()).
      max_tools              — hard cap; matches the static selector.
      always_include         — tool names that MUST be in the result
                               regardless of similarity score
                               (e.g. run_command, recall_similar_
                               experiences). Mirrors ALWAYS_INCLUDE
                               from tool_budget.
      confidence_threshold   — minimum cosine similarity to keep a
                               tool. 0.35 by default.
      min_high_confidence    — if fewer hits clear the threshold,
                               we treat the query as ambiguous and
                               return None.

    Side effects: logs at debug. No I/O beyond what `embedder.embed_query`
    does (network call to Ollama in production).
    """
    if not index:
        logger.debug("ITR: empty index, falling back")
        return None

    try:
        query_vec = embedder.embed_query(query)
    except Exception as exc:
        logger.debug("ITR: embedder failed (%s); falling back", exc)
        return None

    if not query_vec:
        logger.debug("ITR: embedder returned empty vector; falling back")
        return None

    matches = rank_tools(query_vec, index)
    high_conf = [m for m in matches if m.similarity >= confidence_threshold]

    if len(high_conf) < min_high_confidence:
        logger.debug(
            "ITR: only %d/%d hits above %.2f threshold; falling back",
            len(high_conf),
            min_high_confidence,
            confidence_threshold,
        )
        return None

    # Always-include names jump the queue regardless of similarity.
    # The cap counts them. If always_include alone exceeds max_tools,
    # we keep them all and skip ITR results — that's a configuration
    # smell but not a crash.
    selected: list[str] = []
    seen: set[str] = set()
    for name in sorted(always_include):
        if name in index and name not in seen:
            selected.append(name)
            seen.add(name)

    remaining_budget = max(0, max_tools - len(selected))
    for match in high_conf:
        if remaining_budget == 0:
            break
        if match.tool_name in seen:
            continue
        selected.append(match.tool_name)
        seen.add(match.tool_name)
        remaining_budget -= 1

    logger.debug(
        "ITR: selected %d tools (top sim=%.3f, cut=%.3f)",
        len(selected),
        high_conf[0].similarity,
        confidence_threshold,
    )
    return selected
