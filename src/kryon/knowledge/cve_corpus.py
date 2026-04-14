"""
CVE-diff corpus — a dedicated ChromaDB collection separate from the
general knowledge base.

Why a separate collection
-------------------------
The existing `kryon_knowledge` collection mixes ExploitDB, OWASP, CWE
descriptions — useful for general RAG, but noisy when the 0-day hunter
wants "show me past fixes that touched code like this". This module
owns `kryon_cve_diffs` — enriched CVE patches only.

Pipeline
--------
  github_advisory_scraper.scrape()    # advisories from GHSA DB
     -> cve_diff_enricher.enrich_batch()   # fetch fix commit diffs
        -> cve_corpus.ingest_jsonl()       # THIS MODULE — into ChromaDB
           -> recall_similar_code_pattern(code)  # @function_tool used by hunter

Each record is indexed by its `pattern` field (a short summary + diff
snippet) so semantic search over this corpus finds patches that touch
similar code patterns, not just similar natural-language descriptions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


# -- Collection config -------------------------------------------------------

_CORPUS_DIR = Path(os.environ.get(
    "KRYON_CVE_CORPUS_DIR",
    "/workspace/.kryon_cve_corpus",
))
_COLLECTION_NAME = "kryon_cve_diffs"


# -- Singletons --------------------------------------------------------------

_client = None
_collection = None
_embedder = None


def _build_embedder():
    """Ollama-backed embedding function, reused across calls."""
    import os as _os
    embed_url = _os.environ.get("KRYON_EMBEDDING_BASE_URL")
    embed_model = _os.environ.get("KRYON_EMBEDDING_MODEL", "nomic-embed-text")
    if not embed_url:
        return None

    from chromadb.api.types import Documents, EmbeddingFunction, Embeddings
    import requests

    class _OllamaEmbed(EmbeddingFunction[Documents]):
        def __init__(self, base_url: str, model: str) -> None:
            self._url = base_url.rstrip("/") + "/api/embeddings"
            self._model = model

        def __call__(self, input: Documents) -> Embeddings:
            out: Embeddings = []
            for text in input:
                r = requests.post(
                    self._url,
                    json={"model": self._model, "prompt": text},
                    timeout=60,
                )
                r.raise_for_status()
                out.append(r.json()["embedding"])
            return out

        def name(self) -> str:
            return f"ollama-http:{self._model}"

    return _OllamaEmbed(embed_url, embed_model)


def _get_collection():
    global _client, _collection, _embedder
    if _collection is not None:
        return _collection

    import chromadb

    _CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    _client = chromadb.PersistentClient(path=str(_CORPUS_DIR))

    if _embedder is None:
        _embedder = _build_embedder()

    kwargs: dict = {
        "name": _COLLECTION_NAME,
        "metadata": {"description": "CVE-with-diff corpus for 0-day hunter"},
    }
    if _embedder is not None:
        kwargs["embedding_function"] = _embedder

    try:
        _collection = _client.get_or_create_collection(**kwargs)
    except Exception as e:
        # Same embedding-function-mismatch dance as the main KB
        if "embedding function" in str(e).lower() and _embedder is not None:
            try:
                _client.delete_collection(name=_COLLECTION_NAME)
            except Exception:
                pass
            _collection = _client.create_collection(**kwargs)
        else:
            raise

    return _collection


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def _entry_id(entry: dict) -> str:
    """Stable ID derived from ghsa + sha so re-ingests are idempotent."""
    base = f"{entry.get('ghsa_id', '')}|{entry.get('commit_sha', '')}"
    return "cve_" + hashlib.sha1(base.encode()).hexdigest()[:16]


def _entry_metadata(entry: dict) -> dict:
    """Produce a ChromaDB-safe metadata dict (primitives only, no lists)."""
    return {
        "ghsa_id":   entry.get("ghsa_id", "")[:200],
        "cve_id":    entry.get("cve_id", "")[:40],
        "cwe_ids":   ",".join(entry.get("cwe_ids") or [])[:200],
        "severity":  entry.get("severity", "")[:20],
        "ecosystem": entry.get("ecosystem", "")[:40],
        "package":   entry.get("package", "")[:100],
        "repo":      entry.get("repo", "")[:200],
        "commit_sha": entry.get("commit_sha", "")[:40],
        "files_changed": ",".join(
            f.get("path", "") for f in (entry.get("files") or [])
        )[:500],
    }


def ingest_entries(entries: Iterable[dict], *, batch_size: int = 64) -> int:
    """Upsert a batch of enriched entries into the corpus.

    Returns the count added. Re-ingesting the same (ghsa, sha) is a no-op
    (upsert semantics via Chroma's add with conflict).
    """
    coll = _get_collection()
    buf_ids: list[str] = []
    buf_docs: list[str] = []
    buf_meta: list[dict] = []
    total = 0

    def _flush():
        nonlocal total
        if not buf_ids:
            return
        try:
            # upsert when available, else add with ignore-on-conflict semantics
            if hasattr(coll, "upsert"):
                coll.upsert(ids=buf_ids, documents=buf_docs, metadatas=buf_meta)
            else:
                coll.add(ids=buf_ids, documents=buf_docs, metadatas=buf_meta)
            total += len(buf_ids)
        except Exception as e:
            # "ID already exists" — try one-by-one
            logger.debug("batch add failed (%s); retrying individually", e)
            for i, d, m in zip(buf_ids, buf_docs, buf_meta):
                try:
                    if hasattr(coll, "upsert"):
                        coll.upsert(ids=[i], documents=[d], metadatas=[m])
                    else:
                        coll.add(ids=[i], documents=[d], metadatas=[m])
                    total += 1
                except Exception as ie:
                    logger.warning("skip id=%s: %s", i[:20], ie)
        buf_ids.clear()
        buf_docs.clear()
        buf_meta.clear()

    # Cap individual documents at ~5000 chars before embedding.
    # Observed 9/99 failures on the first 100-entry run when patterns were
    # 8KB+ — Ollama's embedding endpoint returned 500 on oversized input.
    # The head of the pattern (summary, CWE tag, commit subject, first file
    # diff) carries the signal; trailing diff hunks add little recall value.
    _MAX_DOC_CHARS = int(os.environ.get("KRYON_CVE_CORPUS_MAX_DOC_CHARS", "5000"))

    for entry in entries:
        doc = entry.get("pattern") or ""
        if not doc.strip():
            continue
        if len(doc) > _MAX_DOC_CHARS:
            doc = doc[:_MAX_DOC_CHARS] + "\n[... truncated for embedding ...]"
        buf_ids.append(_entry_id(entry))
        buf_docs.append(doc)
        buf_meta.append(_entry_metadata(entry))
        if len(buf_ids) >= batch_size:
            _flush()
    _flush()
    return total


def ingest_jsonl(path: str, *, batch_size: int = 64) -> int:
    """Load enriched JSONL (one JSON per line) and ingest."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)

    def _iter():
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("skip malformed line")
    return ingest_entries(_iter(), batch_size=batch_size)


def corpus_stats() -> dict:
    """Summary of what's in the corpus."""
    try:
        coll = _get_collection()
        return {
            "count": coll.count(),
            "persist_dir": str(_CORPUS_DIR),
            "collection": _COLLECTION_NAME,
        }
    except Exception as e:
        return {"error": str(e)[:200]}


def reset_corpus() -> None:
    """Wipe the collection. Meant for testing or re-ingestion."""
    global _client, _collection
    try:
        coll = _get_collection()
        if hasattr(coll, "delete"):
            # Delete everything — Chroma needs a filter; the easiest path
            # is recreating the collection
            pass
        if _client is not None:
            try:
                _client.delete_collection(name=_COLLECTION_NAME)
            except Exception:
                pass
    finally:
        _collection = None


# ---------------------------------------------------------------------------
# Retrieval — the tool the 0-day-hunter actually calls
# ---------------------------------------------------------------------------


def _query_similar(code_snippet: str, top_k: int = 5) -> list[dict]:
    """Backend: returns top_k most similar CVE entries."""
    if not code_snippet.strip():
        return []
    coll = _get_collection()
    if coll.count() == 0:
        return []
    try:
        res = coll.query(
            query_texts=[code_snippet[:6000]],
            n_results=top_k,
        )
    except Exception as e:
        logger.warning("cve corpus query failed: %s", e)
        return []

    out: list[dict] = []
    ids = (res.get("ids") or [[]])[0]
    docs = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]
    for i, doc, meta, dist in zip(ids, docs, metas, dists):
        similarity = max(0.0, 1.0 - float(dist)) if dist is not None else None
        out.append({
            "id": i,
            "cve_id": meta.get("cve_id", ""),
            "ghsa_id": meta.get("ghsa_id", ""),
            "cwe_ids": meta.get("cwe_ids", ""),
            "severity": meta.get("severity", ""),
            "repo": meta.get("repo", ""),
            "commit_sha": meta.get("commit_sha", "")[:10],
            "files_changed": meta.get("files_changed", ""),
            "similarity": similarity,
            "pattern_excerpt": doc[:1500],
        })
    return out


@function_tool(strict_mode=False)
def recall_similar_code_pattern(
    code_snippet: str,
    top_k: int = 5,
) -> str:
    """Find past CVE fixes whose patched code looks like this snippet.

    Use this in the 0-day hunter loop: pass a function you suspect is
    vulnerable, get back the most semantically similar CVE patches from
    the corpus. If one looks like a twin of your function, the bug class
    almost certainly applies here too — go verify with run_sandboxed.

    Args:
        code_snippet: The function body (or a hunk) you want matches for.
        top_k: Max matches to return (default 5).

    Returns JSON: {count, matches: [{cve_id, cwe_ids, severity, repo,
      commit_sha, similarity, pattern_excerpt}]}.
    """
    matches = _query_similar(code_snippet, top_k=max(1, min(int(top_k or 5), 20)))
    return json.dumps({
        "count": len(matches),
        "matches": matches,
    }, indent=2)
