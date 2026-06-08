"""Learning-store resilience: stale embedding dimension (768 vs 384) must not
crash the writeback — recreate the collection + retry."""

from __future__ import annotations

import kryon.learning.experiences as ex
import kryon.learning.findings_library as fl


class _RaisingColl:
    def add(self, **kw):
        raise RuntimeError("Embedding dimension 384 does not match collection dimensionality 768")

    def upsert(self, **kw):
        raise RuntimeError("Collection expecting embedding with dimension of 768, got 384")


class _OKColl:
    def __init__(self):
        self.writes = []

    def add(self, **kw):
        self.writes.append(kw)

    def upsert(self, **kw):
        self.writes.append(kw)


def test_is_embed_mismatch_matches_dimension_and_function():
    assert ex._is_embed_mismatch(RuntimeError("embedding dimension mismatch 768 vs 384"))
    assert ex._is_embed_mismatch(RuntimeError("Embedding function conflict"))
    assert not ex._is_embed_mismatch(RuntimeError("disk full"))


def test_add_experience_recovers_on_dimension_mismatch(monkeypatch):
    ok = _OKColl()
    monkeypatch.setattr(ex, "_get_collection", lambda: _RaisingColl())
    monkeypatch.setattr(ex, "_recreate_collection", lambda: ok)

    rid = ex.add_experience({"host": "10.0.0.1", "outcome": "success", "chain": []})

    assert rid.startswith("eng_")
    assert ok.writes, "writeback should retry on the recreated collection"


def test_add_finding_recovers_on_dimension_mismatch(monkeypatch):
    ok = _OKColl()
    monkeypatch.setattr(fl, "_get_collection", lambda: _RaisingColl())
    monkeypatch.setattr(fl, "_recreate_collection", lambda: ok)

    fid = fl.add_finding({"cwe_id": "CWE-89", "host": "10.0.0.1", "title": "SQLi"})

    assert fid
    assert ok.writes, "findings upsert should retry on the recreated collection"


def test_non_embedding_error_still_raises(monkeypatch):
    class _DiskFull:
        def add(self, **kw):
            raise RuntimeError("No space left on device")

    monkeypatch.setattr(ex, "_get_collection", lambda: _DiskFull())
    import pytest

    with pytest.raises(RuntimeError, match="No space left"):
        ex.add_experience({"host": "x", "outcome": "fail"})
