"""
Experience store — persistent ChromaDB-backed collection of engagement
outcomes. Separate collection from `kryon_knowledge` so that mined attack
chains never mix with static seed data.

See `docs/LEARNING_LOOP.md` for the data model.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "kryon_experiences"
_DEFAULT_PERSIST_DIR = ".kryon_knowledge/chromadb"

# Lazily-initialized module-level client + collection
_client = None
_collection = None


def _get_collection():
    """Return the `kryon_experiences` ChromaDB collection, creating it on
    first access. Uses the same Ollama HTTP embedder as the knowledge base
    when KRYON_EMBEDDING_BASE_URL is set.
    """
    global _client, _collection
    if _collection is not None:
        return _collection

    import chromadb

    persist_dir = Path(os.environ.get("KRYON_EXPERIENCES_DIR", _DEFAULT_PERSIST_DIR))
    persist_dir.mkdir(parents=True, exist_ok=True)
    _client = chromadb.PersistentClient(path=str(persist_dir))

    embed_fn = _build_embedding_function()
    kwargs: dict[str, Any] = {
        "name": _COLLECTION_NAME,
        "metadata": {
            "description": "KRYON engagement experiences",
            "hnsw:space": "cosine",  # cosine distance [0,2] instead of L2
        },
    }
    if embed_fn is not None:
        kwargs["embedding_function"] = embed_fn

    try:
        _collection = _client.get_or_create_collection(**kwargs)
    except Exception as ce:
        # Same recovery path as kryon.knowledge.simple_vector_db: if a
        # prior run persisted a different embedding fn, recreate the
        # collection with ours.
        if "embedding function" in str(ce).lower() and embed_fn is not None:
            try:
                _client.delete_collection(name=_COLLECTION_NAME)
            except Exception:
                pass
            _collection = _client.create_collection(**kwargs)
        else:
            raise

    return _collection


def _build_embedding_function():
    """Build the same Ollama HTTP embedding function used by the knowledge
    base. Returns None when no embedding backend is configured — callers
    then fall back to ChromaDB's default.
    """
    embed_url = os.environ.get("KRYON_EMBEDDING_BASE_URL")
    if not embed_url:
        return None

    embed_model = os.environ.get("KRYON_EMBEDDING_MODEL", "nomic-embed-text")

    import requests
    from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

    class _OllamaHTTPEmbeddingFunction(EmbeddingFunction[Documents]):
        def __init__(self, base_url: str, model: str, timeout: int = 60):
            self._url = base_url.rstrip("/") + "/api/embeddings"
            self._model = model
            self._timeout = timeout

        def __call__(self, input: Documents) -> Embeddings:
            out: Embeddings = []
            for text in input:
                resp = requests.post(
                    self._url,
                    json={"model": self._model, "prompt": text},
                    timeout=self._timeout,
                )
                resp.raise_for_status()
                out.append(resp.json()["embedding"])
            return out

        def name(self) -> str:  # pragma: no cover
            return f"ollama-http:{self._model}"

    return _OllamaHTTPEmbeddingFunction(embed_url, embed_model)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _profile_to_text(profile: dict[str, Any]) -> str:
    """Turn a target profile dict into a human-readable blob used for
    similarity search."""
    parts: list[str] = []
    if profile.get("host"):
        parts.append(f"host={profile['host']}")
    if profile.get("resolved_ip"):
        parts.append(f"ip={profile['resolved_ip']}")
    ports = profile.get("ports") or []
    if ports:
        parts.append("ports=" + ",".join(str(p) for p in ports))
    services = profile.get("services") or {}
    if services:
        svc_blob = " ".join(f"{k}:{v}" for k, v in services.items())
        parts.append(f"services={svc_blob}")
    tech = profile.get("tech") or []
    if tech:
        parts.append("tech=" + ",".join(tech))
    if profile.get("os_hint"):
        parts.append(f"os={profile['os_hint']}")
    if profile.get("asn"):
        parts.append(f"asn={profile['asn']}")
    if profile.get("notes"):
        parts.append(f"notes={profile['notes']}")
    return " | ".join(parts)


def _chain_to_text(chain: list[dict[str, Any]]) -> str:
    """Turn an attack chain into a short textual representation."""
    if not chain:
        return ""
    steps = []
    for step in chain:
        tool = step.get("tool", "?")
        args = step.get("args", "")
        status = step.get("status", "")
        steps.append(f"{tool}({args})={status}")
    return " -> ".join(steps)


def _build_document(experience: dict[str, Any]) -> str:
    """Compose the text blob that gets embedded for similarity search."""
    profile = experience.get("target_profile", {}) or {}
    chain = experience.get("chain", []) or []
    summary = experience.get("summary", "") or ""
    outcome = experience.get("outcome", "unknown")

    lines = [
        f"[profile] {_profile_to_text(profile)}",
        f"[outcome] {outcome}",
        f"[chain] {_chain_to_text(chain)}",
    ]
    if summary:
        lines.append(f"[summary] {summary}")
    return "\n".join(lines)


def _jsonable_metadata(experience: dict[str, Any]) -> dict[str, Any]:
    """ChromaDB metadata must be flat str/int/float/bool. We serialize the
    structured bits to JSON strings so we can roundtrip them."""
    created_at = experience.get("created_at") or datetime.now(timezone.utc).isoformat()
    return {
        "id": experience.get("id"),
        "created_at": created_at,
        "host": (experience.get("target_profile") or {}).get("host", ""),
        "resolved_ip": (experience.get("target_profile") or {}).get("resolved_ip", ""),
        "outcome": experience.get("outcome", "unknown"),
        "duration_s": int(experience.get("duration_s") or 0),
        "agent_path": ",".join(experience.get("agent_path") or []),
        "chain_len": len(experience.get("chain") or []),
        "summary": experience.get("summary", ""),
        # Structured data that won't fit in flat metadata, JSON-encoded
        "_profile_json": json.dumps(experience.get("target_profile") or {}, ensure_ascii=False),
        "_chain_json": json.dumps(experience.get("chain") or [], ensure_ascii=False),
        "_signals_json": json.dumps(experience.get("outcome_signals") or {}, ensure_ascii=False),
    }


def _metadata_to_experience(metadata: dict[str, Any], document: str) -> dict[str, Any]:
    """Rehydrate an experience dict from ChromaDB metadata + document."""
    try:
        profile = json.loads(metadata.get("_profile_json") or "{}")
    except Exception:
        profile = {}
    try:
        chain = json.loads(metadata.get("_chain_json") or "[]")
    except Exception:
        chain = []
    try:
        signals = json.loads(metadata.get("_signals_json") or "{}")
    except Exception:
        signals = {}

    return {
        "id": metadata.get("id"),
        "created_at": metadata.get("created_at"),
        "target_profile": profile,
        "chain": chain,
        "outcome": metadata.get("outcome"),
        "outcome_signals": signals,
        "agent_path": (metadata.get("agent_path") or "").split(",") if metadata.get("agent_path") else [],
        "duration_s": metadata.get("duration_s", 0),
        "summary": metadata.get("summary", ""),
        "document": document,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def add_experience(experience: dict[str, Any]) -> str:
    """Persist one engagement experience. Returns its id.

    The input dict follows the schema in docs/LEARNING_LOOP.md. Missing
    fields get sensible defaults. `id` is assigned if not provided.
    """
    experience = dict(experience)  # don't mutate caller
    if not experience.get("id"):
        experience["id"] = f"eng_{uuid.uuid4().hex[:12]}"
    if not experience.get("created_at"):
        experience["created_at"] = datetime.now(timezone.utc).isoformat()

    document = _build_document(experience)
    metadata = _jsonable_metadata(experience)

    collection = _get_collection()
    collection.add(
        documents=[document],
        metadatas=[metadata],
        ids=[experience["id"]],
    )
    logger.info(
        "Experience %s stored (host=%s outcome=%s chain_len=%d)",
        experience["id"],
        metadata.get("host"),
        metadata.get("outcome"),
        metadata.get("chain_len"),
    )
    return experience["id"]


def recall_similar(
    profile_or_query: dict[str, Any] | str,
    k: int = 3,
    where: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Retrieve the top-k most similar past experiences.

    Accepts either a profile dict (will be serialized) or a free-text
    query string. Returns a list of experience dicts, ordered by
    similarity (best first). Empty list on cold start.
    """
    if isinstance(profile_or_query, dict):
        query_text = _profile_to_text(profile_or_query)
    else:
        query_text = str(profile_or_query)

    if not query_text.strip():
        return []

    collection = _get_collection()
    if collection.count() == 0:
        return []

    try:
        results = collection.query(
            query_texts=[query_text],
            n_results=max(1, int(k)),
            where=where,
        )
    except Exception as e:
        logger.warning("recall_similar failed: %s", e)
        return []

    out: list[dict[str, Any]] = []
    docs = results.get("documents") or [[]]
    metas = results.get("metadatas") or [[]]
    dists = results.get("distances") or [[]]
    for i, doc in enumerate(docs[0]):
        metadata = metas[0][i] if i < len(metas[0]) else {}
        exp = _metadata_to_experience(metadata, doc)
        # Cosine distance range is [0, 2]. Normalize to [0, 1] similarity.
        dist = dists[0][i] if i < len(dists[0]) else 0.0
        exp["score"] = max(0.0, 1.0 - dist / 2.0)
        out.append(exp)
    return out


def list_experiences(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent experiences (up to `limit`), newest first."""
    collection = _get_collection()
    total = collection.count()
    if total == 0:
        return []

    all_rows = collection.get(limit=min(limit * 4, total))
    rows: list[dict[str, Any]] = []
    for i, doc in enumerate(all_rows["documents"]):
        metadata = all_rows["metadatas"][i] if i < len(all_rows["metadatas"]) else {}
        rows.append(_metadata_to_experience(metadata, doc))

    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return rows[:limit]


def get_experience(experience_id: str) -> Optional[dict[str, Any]]:
    """Return a single experience by id, or None."""
    collection = _get_collection()
    try:
        result = collection.get(ids=[experience_id])
    except Exception:
        return None
    if not result["ids"]:
        return None
    return _metadata_to_experience(result["metadatas"][0], result["documents"][0])


def delete_experience(experience_id: str) -> bool:
    """Delete an experience by id. Returns True if found."""
    collection = _get_collection()
    existing = collection.get(ids=[experience_id])
    if not existing["ids"]:
        return False
    collection.delete(ids=[experience_id])
    logger.info("Experience %s deleted", experience_id)
    return True


def count_experiences() -> int:
    """Total number of experiences in the store."""
    return _get_collection().count()
