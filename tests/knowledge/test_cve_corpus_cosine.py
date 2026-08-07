"""The 0-day corpus collection must be created with cosine space.

Regression (T4-C3): without hnsw:space=cosine the ChromaDB default is L2 (squared
euclidean); the `similarity = 1 - distance` mapping is only valid for cosine, so with
non-normalized vectors similarity clamped to 0 for everything and the novelty_gate
always reported 'likely-novel'."""

from __future__ import annotations

from kryon.knowledge import cve_corpus


def test_collection_created_with_cosine_space(monkeypatch):
    import chromadb

    captured = {}

    class FakeClient:
        def get_or_create_collection(self, **kwargs):
            captured["kwargs"] = kwargs
            return object()

    monkeypatch.setattr(chromadb, "PersistentClient", lambda **kw: FakeClient())
    monkeypatch.setattr(cve_corpus, "_collection", None)
    monkeypatch.setattr(cve_corpus, "_embedder", None)
    # No embedder → no embedding_function passed → chromadb doesn't validate one.
    monkeypatch.setattr(cve_corpus, "_build_embedder", lambda: None)

    cve_corpus._get_collection()
    assert captured["kwargs"]["metadata"].get("hnsw:space") == "cosine"
