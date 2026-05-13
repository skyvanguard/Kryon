"""F84.7 — Offline indexer for ITR: embed tool docstrings, persist to
disk, load back on demand.

The indexer is invoked manually (or by an installer / CI job) — NOT
on the hot path of an engagement. Embedding 200+ tool docstrings
takes ~10 seconds with nomic-embed-text; doing it at every Kryon
boot would add measurable startup cost on banca-grade workstations.

Index format: numpy .npz (one array per tool name, shape (D,)). We
deliberately avoid pickle to keep the index banca-safe — pickle.load
on a tampered file would execute arbitrary code. numpy.load(npz) is
documented to refuse pickled objects when `allow_pickle=False`
(the default).

Storage path: $KRYON_HOME/itr_index.npz, default ~/.kryon/itr_index.npz.

Embedder default: Ollama nomic-embed-text (matches
KRYON_EMBEDDING_MODEL in docker/.env.docker). When Ollama is
unreachable we raise — the indexer is offline tooling, the caller
chose to invoke it explicitly and silently producing an empty index
would corrupt the retriever later.

Hash-based invalidation: each tool's docstring is hashed (SHA-256) and
the per-tool hashes plus the embedder identity are stored in a
sibling .json sidecar. `is_index_stale()` re-hashes the registry and
returns True when anything changed — letting an installer rebuild
only when necessary.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from kryon.skills.itr_retriever import Embedder, ToolIndex

logger = logging.getLogger(__name__)

__all__ = [
    "OllamaEmbedder",
    "DEFAULT_INDEX_PATH",
    "DEFAULT_EMBEDDING_MODEL",
    "build_index",
    "save_index",
    "load_index",
    "is_index_stale",
    "tool_doc_for_index",
]


DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"


def _resolve_default_index_path() -> Path:
    """Mirror knowledge/datasets/__init__.py path resolution: prefer
    $KRYON_HOME/itr_index.npz; default ~/.kryon/itr_index.npz."""
    kryon_home = os.environ.get("KRYON_HOME") or str(Path.home() / ".kryon")
    return Path(kryon_home) / "itr_index.npz"


DEFAULT_INDEX_PATH: Path = _resolve_default_index_path()


def tool_doc_for_index(tool: Any) -> str:
    """Build the text we embed for a tool. We pull name + description
    + params_json_schema description fields if present — that gives
    the embedder both the surface name ("nmap") and the semantic
    purpose ("port and service discovery scanner") so query-time
    matching works for both styles of user query.

    Defensive: tools come from a heterogeneous registry; missing
    fields should NOT raise. Returns the tool name on its own as the
    minimal viable doc."""
    parts: list[str] = []
    name = getattr(tool, "name", None) or "<unknown>"
    parts.append(name)
    description = getattr(tool, "description", None)
    if isinstance(description, str) and description.strip():
        parts.append(description.strip())
    schema = getattr(tool, "params_json_schema", None)
    if isinstance(schema, dict):
        # The top-level "description" of the schema is usually the
        # most informative — parameter descriptions are individually
        # short and add noise.
        schema_desc = schema.get("description")
        if isinstance(schema_desc, str) and schema_desc.strip():
            parts.append(schema_desc.strip())
    return " — ".join(parts)


def _hash_doc(doc: str) -> str:
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()


def _sidecar_path(index_path: Path) -> Path:
    """Hash sidecar lives next to the .npz with the same stem +
    .meta.json. is_index_stale reads this; save_index writes it."""
    return index_path.with_suffix(".meta.json")


# ---------------------------------------------------------------------------
# Ollama embedder
# ---------------------------------------------------------------------------


class OllamaEmbedder:
    """Concrete Embedder that calls Ollama's /api/embeddings endpoint
    via the `ollama` package (already a dependency via langchain /
    knowledge module). Falls back to direct HTTP if the package is
    not installed, so a minimal install still works.

    The embedder is stateless apart from caching the model name and
    host. Constructor does NOT make a network call — that's deferred
    to the first embed_query."""

    def __init__(
        self,
        model: str = DEFAULT_EMBEDDING_MODEL,
        host: str | None = None,
    ) -> None:
        self.model = model
        # KRYON_OLLAMA_HOST takes precedence; falls back to ollama
        # package default (localhost:11434).
        self.host = host or os.environ.get("KRYON_OLLAMA_HOST", "http://localhost:11434")

    def embed_query(self, text: str) -> list[float]:
        """Embed `text`. Raises on any network / parsing failure so
        the caller can fall back deterministically."""
        # Try the ollama package first (canonical path).
        try:
            import ollama  # type: ignore[import-not-found]

            client = ollama.Client(host=self.host)
            response = client.embeddings(model=self.model, prompt=text)
            vec = response.get("embedding")
            if not vec:
                raise RuntimeError("ollama returned empty embedding")
            return list(vec)
        except ImportError:
            pass

        # Stdlib fallback — works without the optional ollama dep.
        import json as _json
        import urllib.request

        url = self.host.rstrip("/") + "/api/embeddings"
        payload = _json.dumps({"model": self.model, "prompt": text}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        vec = data.get("embedding")
        if not vec:
            raise RuntimeError(f"ollama /api/embeddings returned no embedding: {data!r}")
        return list(vec)


# ---------------------------------------------------------------------------
# Build / save / load / freshness
# ---------------------------------------------------------------------------


def build_index(
    registry: dict[str, Any],
    embedder: Embedder,
) -> tuple[ToolIndex, dict[str, str]]:
    """Embed every tool's index-doc. Returns (index, doc_hashes).

    Tools without an embeddable doc string are skipped with a debug
    log — the retriever ignores them naturally because they don't
    appear in the index."""
    index: ToolIndex = {}
    doc_hashes: dict[str, str] = {}
    for name, tool in sorted(registry.items()):
        doc = tool_doc_for_index(tool)
        if not doc.strip():
            logger.debug("ITR index: skipping %s (empty doc)", name)
            continue
        try:
            vec = embedder.embed_query(doc)
        except Exception as exc:
            # Skip individual tool failures so the index isn't held
            # hostage by one malformed doc; warn so curators see it.
            logger.warning("ITR index: embedder failed on %s (%s); skipping", name, exc)
            continue
        if not vec:
            logger.warning("ITR index: empty vector for %s; skipping", name)
            continue
        index[name] = list(vec)
        doc_hashes[name] = _hash_doc(doc)
    return index, doc_hashes


def save_index(
    index: ToolIndex,
    doc_hashes: dict[str, str],
    *,
    path: Path | None = None,
    embedder_model: str = DEFAULT_EMBEDDING_MODEL,
) -> Path:
    """Persist `index` to `path` (default DEFAULT_INDEX_PATH) as .npz
    plus a sidecar .meta.json with per-tool doc hashes + embedder
    identity. Returns the path written."""
    import numpy as np

    out_path = path or DEFAULT_INDEX_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)

    np.savez(
        out_path,
        **{name: np.asarray(vec, dtype=np.float32) for name, vec in index.items()},
    )
    sidecar = {
        "embedder_model": embedder_model,
        "doc_hashes": doc_hashes,
        "tool_count": len(index),
    }
    _sidecar_path(out_path).write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    return out_path


def load_index(path: Path | None = None) -> ToolIndex:
    """Load a previously-saved index from `path` (default
    DEFAULT_INDEX_PATH). Returns an empty dict if the file does not
    exist — the retriever then short-circuits to None and the caller
    falls back to static selection."""
    import numpy as np

    in_path = path or DEFAULT_INDEX_PATH
    if not in_path.is_file():
        return {}
    with np.load(in_path, allow_pickle=False) as npz:
        return {name: npz[name].tolist() for name in npz.files}


def is_index_stale(
    registry: dict[str, Any],
    *,
    path: Path | None = None,
    embedder_model: str = DEFAULT_EMBEDDING_MODEL,
) -> bool:
    """Return True when (a) no sidecar exists, (b) the embedder model
    string changed, (c) any tool's docstring hash changed, or (d) the
    set of tool names in the registry differs from the sidecar.

    Lets an installer skip a costly rebuild when nothing meaningful
    changed between Kryon versions."""
    sidecar = _sidecar_path(path or DEFAULT_INDEX_PATH)
    if not sidecar.is_file():
        return True
    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return True
    if meta.get("embedder_model") != embedder_model:
        return True
    stored_hashes = meta.get("doc_hashes", {})
    current_hashes = {
        name: _hash_doc(tool_doc_for_index(tool))
        for name, tool in registry.items()
        if tool_doc_for_index(tool).strip()
    }
    if set(stored_hashes) != set(current_hashes):
        return True
    return stored_hashes != current_hashes
