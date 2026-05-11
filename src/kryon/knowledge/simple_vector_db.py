"""
KRYON Simple Vector Database
==============================

Lightweight vector database implementation for Python 3.14 compatibility.
Falls back when ChromaDB is unavailable.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

import json
import logging
import pickle
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

_windows_encoding_fixed = False


def _fix_windows_encoding() -> None:
    """Apply UTF-8 encoding fix for Windows stdout/stderr (once)."""
    global _windows_encoding_fixed
    if _windows_encoding_fixed or sys.platform != "win32":
        return
    _windows_encoding_fixed = True
    import codecs

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")


class SimpleVectorDatabase:
    """
    Simple file-based vector database.

    Uses JSON for metadata and pickle for vectors.
    Provides semantic search via cosine similarity.
    """

    def __init__(self, persist_directory: str = ".kryon_knowledge/simple_db"):
        """
        Initialize simple vector database.

        Args:
            persist_directory: Directory to persist database
        """
        _fix_windows_encoding()
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        self.metadata_file = self.persist_directory / "metadata.json"
        self.vectors_file = self.persist_directory / "vectors.pkl"

        # Load or initialize
        self.documents = {}  # id -> document text
        self.metadatas = {}  # id -> metadata
        self.vectors = {}  # id -> embedding vector

        self._load()
        self._embedding_model = None

    def _load(self):
        """Load database from disk.  Corrupted files are removed and re-created."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self.documents = data.get("documents", {})
                    self.metadatas = data.get("metadatas", {})
            except (json.JSONDecodeError, ValueError):
                logging.getLogger(__name__).warning(
                    "Corrupted metadata.json — resetting vector DB: %s",
                    self.metadata_file,
                )
                self.metadata_file.unlink(missing_ok=True)
                self.vectors_file.unlink(missing_ok=True)
                self.documents = {}
                self.metadatas = {}
                return

        if self.vectors_file.exists():
            try:
                with open(self.vectors_file, "rb") as f:
                    self.vectors = pickle.load(f)  # nosec B301 # nosemgrep: avoid-pickle  # noqa: S301
            except Exception:
                logging.getLogger(__name__).warning(
                    "Corrupted vectors.pkl — resetting: %s",
                    self.vectors_file,
                )
                self.vectors_file.unlink(missing_ok=True)
                self.vectors = {}

    def _save(self):
        """Save database to disk."""
        # Save metadata and documents
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(
                {"documents": self.documents, "metadatas": self.metadatas},
                f,
                indent=2,
                ensure_ascii=False,
            )

        # Save vectors
        with open(self.vectors_file, "wb") as f:
            pickle.dump(self.vectors, f)  # nosemgrep: avoid-pickle

    def _get_embedding_model(self):
        """Get or initialize embedding model."""
        if self._embedding_model is None:
            try:
                from sentence_transformers import SentenceTransformer

                self._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
            except ImportError:
                print("⚠️  sentence-transformers not installed")
                print("Install with: pip install sentence-transformers")
                raise
        return self._embedding_model

    def _generate_embedding(self, text: str) -> np.ndarray:
        """Generate embedding for text."""
        model = self._get_embedding_model()
        return model.encode(text, convert_to_numpy=True)

    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = np.dot(vec1, vec2)
        norm_product = np.linalg.norm(vec1) * np.linalg.norm(vec2)
        return dot_product / norm_product if norm_product > 0 else 0.0

    def add_documents(
        self,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> int:
        """
        Add documents to vector database.

        Performance: Uses batch embedding generation for 3-5x speedup.

        Args:
            documents: List of text documents
            metadatas: Optional metadata for each document
            ids: Optional IDs for each document

        Returns:
            Number of documents added
        """
        # Generate IDs if not provided
        if ids is None:
            ids = [f"doc_{int(time.time() * 1000)}_{i}" for i in range(len(documents))]

        # Ensure metadatas
        if metadatas is None:
            metadatas = [{"timestamp": time.time()} for _ in documents]

        # Performance optimization: batch embedding generation
        # This is 3-5x faster than one-by-one encoding
        model = self._get_embedding_model()
        embeddings = model.encode(documents, convert_to_numpy=True, show_progress_bar=False)

        # Add each document with pre-computed embeddings
        for i, doc_id in enumerate(ids):
            self.documents[doc_id] = documents[i]
            self.metadatas[doc_id] = metadatas[i]
            self.vectors[doc_id] = embeddings[i]

        # Save to disk
        self._save()

        return len(documents)

    def query(self, query_text: str, top_k: int = 5, filter_metadata: dict | None = None) -> list[dict[str, Any]]:
        """
        Query vector database with semantic search.

        Args:
            query_text: Query text
            top_k: Number of results to return
            filter_metadata: Optional metadata filter

        Returns:
            List of results with documents, metadata, and scores
        """
        if not self.vectors:
            return []

        # Generate query embedding
        query_vector = self._generate_embedding(query_text)

        # Compute similarities
        results = []
        for doc_id, doc_vector in self.vectors.items():
            # Apply metadata filter if provided
            if filter_metadata:
                match = all(self.metadatas[doc_id].get(key) == value for key, value in filter_metadata.items())
                if not match:
                    continue

            similarity = self._cosine_similarity(query_vector, doc_vector)
            results.append(
                {
                    "id": doc_id,
                    "content": self.documents[doc_id],
                    "metadata": self.metadatas[doc_id],
                    "score": float(similarity),
                }
            )

        # Sort by similarity (descending) and return top_k
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def delete_by_ids(self, ids: list[str]) -> int:
        """
        Delete documents by IDs.

        Args:
            ids: List of document IDs to delete

        Returns:
            Number of documents deleted
        """
        deleted = 0
        for doc_id in ids:
            if doc_id in self.documents:
                del self.documents[doc_id]
                del self.metadatas[doc_id]
                del self.vectors[doc_id]
                deleted += 1

        self._save()
        return deleted

    def delete_by_filter(self, filter_metadata: dict) -> int:
        """
        Delete documents by metadata filter.

        Args:
            filter_metadata: Metadata filter

        Returns:
            Number of documents deleted
        """
        to_delete = []
        for doc_id, metadata in self.metadatas.items():
            match = all(metadata.get(key) == value for key, value in filter_metadata.items())
            if match:
                to_delete.append(doc_id)

        return self.delete_by_ids(to_delete)

    def count(self) -> int:
        """Get total number of documents in database."""
        return len(self.documents)

    def get_stats(self) -> dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Statistics dictionary
        """
        stats = {
            "total_documents": self.count(),
            "persist_directory": str(self.persist_directory),
            "database_type": "simple_vector_db",
        }

        # Get source breakdown
        if self.count() > 0:
            sources = {}
            for metadata in self.metadatas.values():
                source = metadata.get("source", "unknown")
                sources[source] = sources.get(source, 0) + 1
            stats["sources"] = sources

        return stats

    def reset(self):
        """Reset database (delete all documents)."""
        self.documents = {}
        self.metadatas = {}
        self.vectors = {}
        self._save()


# Fallback wrapper that tries ChromaDB first, falls back to simple DB
class VectorDatabase:
    """
    Vector database with automatic fallback.

    Tries to use ChromaDB, falls back to SimpleVectorDatabase if unavailable.
    """

    def __init__(self, persist_directory: str = ".kryon_knowledge/chromadb"):
        """Initialize with automatic fallback."""
        self.backend = None
        self.backend_type = None
        self._client = None
        self._collection = None

        try:
            # Try ChromaDB first
            import chromadb

            persist_path = Path(persist_directory)
            persist_path.mkdir(parents=True, exist_ok=True)

            self._client = chromadb.PersistentClient(path=str(persist_path))

            # Build embedding function. Prefer a local Ollama embedder when
            # KRYON_EMBEDDING_BASE_URL is set (avoids ChromaDB's default ONNX
            # download which needs a writable ~/.cache/chroma).
            import os

            embed_fn = None
            embed_url = os.environ.get("KRYON_EMBEDDING_BASE_URL")
            embed_model = os.environ.get("KRYON_EMBEDDING_MODEL", "nomic-embed-text")
            if embed_url:
                import requests
                from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

                class _OllamaHTTPEmbeddingFunction(EmbeddingFunction[Documents]):
                    """Minimal embedding function that calls Ollama /api/embeddings
                    directly via HTTP. Avoids the `ollama` python SDK dep required
                    by chromadb's built-in OllamaEmbeddingFunction."""

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

                    def name(self) -> str:  # pragma: no cover - informational
                        return f"ollama-http:{self._model}"

                embed_fn = _OllamaHTTPEmbeddingFunction(embed_url, embed_model)

            collection_kwargs: dict[str, Any] = {
                "name": "kryon_knowledge",
                "metadata": {"description": "KRYON knowledge base"},
            }
            if embed_fn is not None:
                collection_kwargs["embedding_function"] = embed_fn

            # Chroma 1.x persists the embedding function config per-collection.
            # If a previous run created the collection with a different
            # (default) embedder, get_or_create_collection refuses to attach
            # a new one. Detect that case and recreate the collection.
            try:
                self._collection = self._client.get_or_create_collection(**collection_kwargs)
            except Exception as ce:
                if "embedding function" in str(ce).lower() and embed_fn is not None:
                    try:
                        self._client.delete_collection(name="kryon_knowledge")
                    except Exception:
                        pass
                    self._collection = self._client.create_collection(**collection_kwargs)
                else:
                    raise
            self.backend = self._collection
            self.backend_type = "chromadb"
            print("✅ Using ChromaDB backend")

        except (ImportError, Exception) as e:
            # Fall back to simple vector database
            print(f"⚠️  ChromaDB unavailable ({e}), using simple vector database")
            self.backend = SimpleVectorDatabase(persist_directory.replace("chromadb", "simple_db"))
            self.backend_type = "simple"
            self._client = None  # Simple backend doesn't have client
            self._collection = None  # Simple backend doesn't have collection
            print("✅ Using SimpleVectorDatabase backend")

    @property
    def client(self):
        """Get ChromaDB client (or None for simple backend)."""
        return self._client

    @property
    def collection(self):
        """Get ChromaDB collection (or None for simple backend)."""
        return self._collection

    def add_documents(
        self,
        documents: list[str],
        metadatas: list[dict] | None = None,
        ids: list[str] | None = None,
    ) -> int:
        """Add documents to backend."""
        if self.backend_type == "chromadb":
            if ids is None:
                ids = [f"doc_{int(time.time() * 1000)}_{i}" for i in range(len(documents))]
            if metadatas is None:
                metadatas = [{"timestamp": time.time()} for _ in documents]
            self.backend.add(documents=documents, metadatas=metadatas, ids=ids)
            return len(documents)
        else:
            return self.backend.add_documents(documents, metadatas, ids)

    def query(self, query_text: str, top_k: int = 5, filter_metadata: dict | None = None) -> list[dict]:
        """Query backend."""
        if self.backend_type == "chromadb":
            results = self.backend.query(query_texts=[query_text], n_results=top_k, where=filter_metadata)
            formatted_results = []
            for i in range(len(results["documents"][0])):
                formatted_results.append(
                    {
                        "id": results["ids"][0][i],
                        "content": results["documents"][0][i],
                        "metadata": results["metadatas"][0][i],
                        "score": 1.0 - results["distances"][0][i],
                    }
                )
            return formatted_results
        else:
            return self.backend.query(query_text, top_k, filter_metadata)

    def delete_by_ids(self, ids: list[str]) -> int:
        """Delete documents by IDs."""
        if self.backend_type == "chromadb":
            self.backend.delete(ids=ids)
            return len(ids)
        else:
            return self.backend.delete_by_ids(ids)

    def delete_by_filter(self, filter_metadata: dict) -> int:
        """Delete documents by filter."""
        if self.backend_type == "chromadb":
            self.backend.delete(where=filter_metadata)
            return 1
        else:
            return self.backend.delete_by_filter(filter_metadata)

    def count(self) -> int:
        """Get document count."""
        if self.backend_type == "chromadb":
            return self.backend.count()
        else:
            return self.backend.count()

    def get_stats(self) -> dict[str, Any]:
        """Get statistics."""
        if self.backend_type == "chromadb":
            stats = {"total_documents": self.count(), "backend_type": "chromadb"}
            if self.count() > 0:
                all_docs = self.backend.get(limit=self.count())
                sources = {}
                for metadata in all_docs["metadatas"]:
                    source = metadata.get("source", "unknown")
                    sources[source] = sources.get(source, 0) + 1
                stats["sources"] = sources
            return stats
        else:
            return self.backend.get_stats()

    def reset(self):
        """Reset database."""
        if self.backend_type == "chromadb":
            # Cannot easily reset chromadb collection
            pass
        else:
            self.backend.reset()


# Global instance
_vector_db = None


def get_vector_db(persist_directory: str = ".kryon_knowledge/chromadb") -> VectorDatabase:
    """Get global vector database instance."""
    global _vector_db
    if _vector_db is None:
        _vector_db = VectorDatabase(persist_directory)
    return _vector_db


# Convenience functions
def add_documents(documents: list[str], **kwargs) -> int:
    """Add documents to vector database."""
    return get_vector_db().add_documents(documents, **kwargs)


def query_db(query_text: str, **kwargs) -> list[dict]:
    """Query vector database."""
    return get_vector_db().query(query_text, **kwargs)
