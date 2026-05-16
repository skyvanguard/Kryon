"""Findings pattern library (F64).

Per-finding ChromaDB collection — the XBOW-style n-days-as-patterns
lookup. Every finding emitted by ``run_web_pentest`` (and future web /
compliance tools) gets indexed here with its CWE + URL shape + probe
id + evidence. Future engagements query this library BEFORE probing
to seed their attack plan with known-working patterns against similar
targets.

Separate from :mod:`kryon.learning.experiences` which stores
engagement-level chains. Findings are finer-grained and queried by
different retrieval keys (CWE class + URL shape + tech fingerprint
rather than full engagement profile).

Storage: ChromaDB collection ``kryon_findings``, Ollama-embedded
document = ``"cwe_id | probe_id | url_shape | title"`` so nearest-
neighbour retrieves both by semantic title overlap AND by URL pattern
similarity.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "kryon_findings"
_DEFAULT_PERSIST_DIR = ".kryon_knowledge/chromadb"

_client = None
_collection = None


# ---------------------------------------------------------------------------
# Collection bootstrap
# ---------------------------------------------------------------------------


def _get_collection():
    """Return the ``kryon_findings`` ChromaDB collection.

    Lazy init so importing this module is cheap; first operation does
    the work.
    """
    global _client, _collection
    if _collection is not None:
        return _collection

    import chromadb  # noqa: PLC0415

    persist_dir = Path(os.environ.get("KRYON_FINDINGS_DIR", _DEFAULT_PERSIST_DIR))
    persist_dir.mkdir(parents=True, exist_ok=True)
    _client = chromadb.PersistentClient(path=str(persist_dir))

    embed_fn = _build_embedding_function()
    kwargs: dict[str, Any] = {
        "name": _COLLECTION_NAME,
        "metadata": {
            "description": "KRYON findings pattern library",
            "hnsw:space": "cosine",
        },
    }
    if embed_fn is not None:
        kwargs["embedding_function"] = embed_fn

    try:
        _collection = _client.get_or_create_collection(**kwargs)
    except Exception as ce:
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
    """Build the same Ollama HTTP embedding function used by the experiences
    store. Returns None when no KRYON_EMBEDDING_BASE_URL is set — in which
    case ChromaDB uses its default all-MiniLM embedder.
    """
    embed_url = os.environ.get("KRYON_EMBEDDING_BASE_URL")
    if not embed_url:
        return None

    try:
        from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
    except ImportError:  # pragma: no cover
        return None

    model = os.environ.get("KRYON_EMBEDDING_MODEL", "nomic-embed-text")
    return OllamaEmbeddingFunction(url=embed_url, model_name=model)


# ---------------------------------------------------------------------------
# URL shape extraction — the retrieval key for "similar target URL"
# ---------------------------------------------------------------------------


_NUMERIC_SEG_RE = re.compile(r"\d+")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def url_shape(url: str) -> str:
    """Normalize URL into a structural pattern for retrieval.

    Examples:
        https://bank.com/api/account/00012345?q=1
          → /api/account/<int>?q=<n>
        https://bank.com/user/550e8400-e29b-41d4-a716-446655440000/profile
          → /user/<uuid>/profile
        https://shop.com/search?q=test
          → /search?q=<n>
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    segments: list[str] = []
    for seg in parsed.path.split("/"):
        if not seg:
            segments.append("")
            continue
        if _UUID_RE.match(seg):
            segments.append("<uuid>")
        elif seg.isdigit():
            segments.append("<int>")
        elif _HEX_RE.match(seg):
            segments.append("<hex>")
        elif re.search(r"\d{4,}", seg) and any(c.isalpha() for c in seg):
            # mixed alnum with a long numeric run (e.g. "acct_12345",
            # "order-98765") — common account/order id shape in LATAM
            # banking. Short prefixes like "v1", "v2" (API version)
            # keep their numeric part intact.
            normed = _NUMERIC_SEG_RE.sub("<n>", seg)
            segments.append(normed)
        else:
            segments.append(seg)

    path = "/".join(segments)

    # Query params — keep param names, mask values
    query = ""
    if parsed.query:
        parts: list[str] = []
        for p in parsed.query.split("&"):
            if "=" in p:
                name = p.split("=", 1)[0]
                parts.append(f"{name}=<n>")
            else:
                parts.append(p)
        query = "?" + "&".join(parts)

    return path + query


# ---------------------------------------------------------------------------
# Document / metadata builders
# ---------------------------------------------------------------------------


def _build_document(finding: dict[str, Any]) -> str:
    """Build the text ChromaDB embeds + searches.

    Composition tuned for nearest-neighbour over both CWE class and
    URL shape simultaneously.
    """
    cwe = finding.get("cwe_id", "")
    probe = finding.get("probe_id", "")
    shape = finding.get("url_shape") or url_shape(finding.get("url", ""))
    title = finding.get("title", "")
    tech = finding.get("tech_fingerprint", "")
    evidence = (finding.get("evidence") or "")[:512]
    return f"{cwe} | {probe} | url={shape} | tech={tech}\ntitle: {title}\nevidence: {evidence}"


def _jsonable_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    """Flatten a finding to ChromaDB-compatible metadata."""
    return {
        "id": finding["id"],
        "created_at": finding["created_at"],
        "engagement_id": finding.get("engagement_id", ""),
        "cwe_id": finding.get("cwe_id", ""),
        "probe_id": finding.get("probe_id", ""),
        "severity": finding.get("severity", ""),
        "status": finding.get("status", ""),
        "url": (finding.get("url") or "")[:512],
        "url_shape": finding.get("url_shape") or url_shape(finding.get("url", "")),
        "host": finding.get("host", ""),
        "title": (finding.get("title") or "")[:256],
        "tech_fingerprint": finding.get("tech_fingerprint", ""),
        # JSON-encoded structured payload that won't fit flat
        "_compliance_json": json.dumps(
            finding.get("compliance_citations") or [],
            ensure_ascii=False,
        ),
        "_evidence_json": json.dumps(
            {
                "evidence": (finding.get("evidence") or "")[:2048],
                "remediation": (finding.get("remediation") or "")[:1024],
            },
            ensure_ascii=False,
        ),
    }


def _metadata_to_finding(metadata: dict[str, Any], document: str) -> dict[str, Any]:
    try:
        citations = json.loads(metadata.get("_compliance_json") or "[]")
    except Exception:
        citations = []
    try:
        ev = json.loads(metadata.get("_evidence_json") or "{}")
    except Exception:
        ev = {}

    return {
        "id": metadata.get("id"),
        "created_at": metadata.get("created_at"),
        "engagement_id": metadata.get("engagement_id"),
        "cwe_id": metadata.get("cwe_id"),
        "probe_id": metadata.get("probe_id"),
        "severity": metadata.get("severity"),
        "status": metadata.get("status"),
        "url": metadata.get("url"),
        "url_shape": metadata.get("url_shape"),
        "host": metadata.get("host"),
        "title": metadata.get("title"),
        "tech_fingerprint": metadata.get("tech_fingerprint"),
        "compliance_citations": citations,
        "evidence": ev.get("evidence", ""),
        "remediation": ev.get("remediation", ""),
        "document": document,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _content_fingerprint(finding: dict[str, Any]) -> str:
    """Deterministic id from (cwe, probe, url_shape, host) so the same
    finding from the same target de-duplicates instead of accumulating."""
    key = "|".join(
        [
            finding.get("cwe_id", ""),
            finding.get("probe_id", ""),
            finding.get("url_shape") or url_shape(finding.get("url", "")),
            finding.get("host", ""),
        ]
    )
    return "fnd_" + hashlib.sha1(key.encode()).hexdigest()[:14]


def add_finding(finding: dict[str, Any]) -> str:
    """Persist one finding record. Returns its id.

    Idempotent: two findings with the same (cwe, probe, url_shape, host)
    get the same id and the new one replaces the old. Keeps the library
    compact across repeat engagements against the same target.
    """
    finding = dict(finding)

    # Normalize url_shape + host up-front
    url = finding.get("url", "")
    if url and not finding.get("url_shape"):
        finding["url_shape"] = url_shape(url)
    if url and not finding.get("host"):
        try:
            finding["host"] = urlparse(url).netloc
        except Exception:
            pass

    if not finding.get("id"):
        finding["id"] = _content_fingerprint(finding)
    if not finding.get("created_at"):
        finding["created_at"] = datetime.now(timezone.utc).isoformat()

    document = _build_document(finding)
    metadata = _jsonable_metadata(finding)

    collection = _get_collection()
    # upsert: if the id exists, replace; otherwise add
    collection.upsert(
        documents=[document],
        metadatas=[metadata],
        ids=[finding["id"]],
    )
    logger.info(
        "Finding %s stored (cwe=%s host=%s shape=%s)",
        finding["id"],
        metadata.get("cwe_id"),
        metadata.get("host"),
        metadata.get("url_shape"),
    )

    # F176 — also append to the per-engagement partial JSONL so the
    # reporting phase can recover findings even if the orchestrator
    # aborts early. No-op when KRYON_ENGAGEMENT_ID isn't set
    # (one-off CLI calls).
    try:
        from kryon.validation.findings_persistence import append_partial_finding

        append_partial_finding(finding)
    except Exception as exc:  # noqa: BLE001 — partial persistence is best-effort
        logger.debug("partial finding persistence failed: %s", exc)

    return finding["id"]


def add_findings_batch(findings: list[dict[str, Any]]) -> list[str]:
    """Persist a batch of findings; returns list of ids."""
    return [add_finding(f) for f in findings]


def recall_similar(
    query: str,
    k: int = 5,
    *,
    filter_cwe: str | None = None,
    filter_tech: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve top-k findings similar to the query string.

    ``query`` is a natural-language or structured string; we embed it
    and search against the findings collection. Filters further narrow
    to a specific CWE class or tech fingerprint.

    Score is in [0, 1]; higher = more similar.
    """
    collection = _get_collection()
    where: dict | None = None
    if filter_cwe and filter_tech:
        where = {"$and": [{"cwe_id": filter_cwe}, {"tech_fingerprint": filter_tech}]}
    elif filter_cwe:
        where = {"cwe_id": filter_cwe}
    elif filter_tech:
        where = {"tech_fingerprint": filter_tech}

    try:
        results = collection.query(
            query_texts=[query],
            n_results=k,
            where=where,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("findings recall failed: %s", exc)
        return []

    ids = (results.get("ids") or [[]])[0]
    metadatas = (results.get("metadatas") or [[]])[0]
    distances = (results.get("distances") or [[]])[0]
    documents = (results.get("documents") or [[]])[0]

    out: list[dict[str, Any]] = []
    for i, meta in enumerate(metadatas):
        finding = _metadata_to_finding(meta, documents[i] if i < len(documents) else "")
        dist = float(distances[i]) if i < len(distances) else 1.0
        # cosine distance ∈ [0, 2]; convert to similarity ∈ [0, 1]
        finding["score"] = max(0.0, 1.0 - dist / 2.0)
        out.append(finding)

    return out


def recall_by_url_shape(shape: str, k: int = 5) -> list[dict[str, Any]]:
    """Fast path: retrieve findings whose url_shape matches verbatim.

    Useful when the planner sees /api/account/<int> and wants to pull
    every prior finding on that exact structural pattern regardless of
    CWE class.
    """
    collection = _get_collection()
    try:
        results = collection.get(
            where={"url_shape": shape},
            limit=k,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("url_shape lookup failed: %s", exc)
        return []

    metadatas = results.get("metadatas") or []
    documents = results.get("documents") or []
    out = []
    for i, meta in enumerate(metadatas):
        out.append(
            _metadata_to_finding(
                meta,
                documents[i] if i < len(documents) else "",
            )
        )
    return out


def count_findings() -> int:
    try:
        return _get_collection().count()
    except Exception:
        return 0


def stats() -> dict[str, Any]:
    """Library health + content summary."""
    collection = _get_collection()
    total = collection.count()
    by_cwe: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_host: dict[str, int] = {}

    if total > 0:
        # ChromaDB .get() returns up to limit findings; we're just
        # counting so pull a reasonable cap
        batch = collection.get(limit=min(total, 5000))
        for meta in batch.get("metadatas") or []:
            cwe = meta.get("cwe_id") or "unknown"
            sev = meta.get("severity") or "unknown"
            host = meta.get("host") or "unknown"
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_host[host] = by_host.get(host, 0) + 1

    return {
        "total_findings": total,
        "by_cwe": dict(sorted(by_cwe.items(), key=lambda x: -x[1])[:20]),
        "by_severity": by_severity,
        "distinct_hosts": len(by_host),
    }


def delete_finding(finding_id: str) -> bool:
    try:
        _get_collection().delete(ids=[finding_id])
        return True
    except Exception:
        return False


def clear_all() -> int:
    """Danger: wipe the entire library. Returns count deleted. Used in tests."""
    collection = _get_collection()
    total = collection.count()
    if total == 0:
        return 0
    batch = collection.get(limit=total)
    ids = batch.get("ids") or []
    if ids:
        collection.delete(ids=ids)
    return len(ids)
