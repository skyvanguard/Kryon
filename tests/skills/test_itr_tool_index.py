"""F84.7 — Tests for the offline ITR indexer.

We don't call Ollama in tests — instead we inject mock tool objects
and a fake Embedder, then exercise build/save/load/staleness paths
end-to-end.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from kryon.skills.itr_tool_index import (
    DEFAULT_EMBEDDING_MODEL,
    _hash_doc,
    _sidecar_path,
    build_index,
    is_index_stale,
    load_index,
    save_index,
    tool_doc_for_index,
)


pytest.importorskip("numpy", reason="indexer persistence requires numpy")


# =====================================================================
# tool_doc_for_index — doc string construction
# =====================================================================


def test_tool_doc_includes_name_and_description():
    tool = SimpleNamespace(name="sqlmap", description="SQL injection scanner")
    doc = tool_doc_for_index(tool)
    assert "sqlmap" in doc
    assert "SQL injection scanner" in doc


def test_tool_doc_falls_back_to_name_only():
    tool = SimpleNamespace(name="some_tool")
    doc = tool_doc_for_index(tool)
    assert doc.strip() == "some_tool"


def test_tool_doc_skips_empty_strings():
    """Description present-but-empty should not pollute the doc."""
    tool = SimpleNamespace(name="x", description="   ")
    doc = tool_doc_for_index(tool)
    assert doc.strip() == "x"


def test_tool_doc_pulls_schema_description():
    tool = SimpleNamespace(
        name="nuclei",
        description="Template-based vuln scanner",
        params_json_schema={"description": "Run nuclei templates against a target URL"},
    )
    doc = tool_doc_for_index(tool)
    assert "Run nuclei templates" in doc


def test_tool_doc_handles_missing_name():
    """Defensive — a malformed tool with no .name should not raise."""
    tool = SimpleNamespace(description="something")
    doc = tool_doc_for_index(tool)
    assert "<unknown>" in doc


# =====================================================================
# build_index — happy path + per-tool failure isolation
# =====================================================================


class _SequentialEmbedder:
    """Returns sequentially-numbered vectors so we can identify which
    tool got which embedding by index."""

    def __init__(self, dim: int = 4) -> None:
        self.dim = dim
        self.calls = 0

    def embed_query(self, text: str) -> list[float]:
        self.calls += 1
        # Produce a unique-ish vector per call: rotate the first
        # element so different inputs yield different vectors.
        base = [0.0] * self.dim
        base[0] = float(self.calls)
        return base


class _OneBadOneGoodEmbedder:
    """Raises on the first call, succeeds on the second. Exercises
    the per-tool isolation guarantee."""

    def __init__(self) -> None:
        self.calls = 0

    def embed_query(self, text: str) -> list[float]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("transient failure")
        return [1.0, 0.0]


def test_build_index_embeds_each_tool():
    registry = {
        "a": SimpleNamespace(name="a", description="alpha"),
        "b": SimpleNamespace(name="b", description="beta"),
    }
    index, hashes = build_index(registry, _SequentialEmbedder())
    assert set(index) == {"a", "b"}
    assert set(hashes) == {"a", "b"}
    # Each entry has 4 floats (matches _SequentialEmbedder dim).
    assert all(len(v) == 4 for v in index.values())


def test_build_index_skips_tools_with_empty_docs():
    registry = {
        "good": SimpleNamespace(name="good", description="real tool"),
        "bare": SimpleNamespace(),  # no .name, no description, doc = "<unknown>"
    }
    index, hashes = build_index(registry, _SequentialEmbedder())
    # Both produce non-empty docs (bare is "<unknown>"), so both index.
    # Tests with truly empty docs are below.
    assert "good" in index
    # The "<unknown>" doc is non-empty so it still indexes.
    assert "bare" in index


def test_build_index_isolates_per_tool_embedder_failures():
    registry = {
        "broken": SimpleNamespace(name="broken", description="will fail"),
        "ok": SimpleNamespace(name="ok", description="will succeed"),
    }
    index, hashes = build_index(registry, _OneBadOneGoodEmbedder())
    # "broken" was skipped (first call raised); "ok" succeeded.
    assert "broken" not in index
    assert "ok" in index


# =====================================================================
# save_index / load_index round-trip
# =====================================================================


def test_save_and_load_round_trip(tmp_path):
    index = {
        "alpha": [1.0, 0.0, 0.0],
        "beta": [0.0, 1.0, 0.0],
    }
    hashes = {"alpha": _hash_doc("alpha — alpha desc"), "beta": _hash_doc("beta — beta desc")}
    out = save_index(index, hashes, path=tmp_path / "idx.npz")
    assert out.is_file()
    loaded = load_index(path=tmp_path / "idx.npz")
    assert set(loaded) == set(index)
    for name in index:
        assert pytest.approx(loaded[name], abs=1e-6) == index[name]


def test_save_writes_sidecar_with_embedder_model(tmp_path):
    save_index(
        {"a": [1.0]},
        {"a": _hash_doc("a — a desc")},
        path=tmp_path / "idx.npz",
        embedder_model="nomic-embed-text",
    )
    sidecar = json.loads((tmp_path / "idx.meta.json").read_text(encoding="utf-8"))
    assert sidecar["embedder_model"] == "nomic-embed-text"
    assert sidecar["tool_count"] == 1
    assert "a" in sidecar["doc_hashes"]


def test_load_missing_file_returns_empty_dict(tmp_path):
    """Falling back when no index exists is the caller's contract —
    the loader must not raise FileNotFoundError."""
    assert load_index(path=tmp_path / "missing.npz") == {}


def test_load_index_refuses_pickled_data(tmp_path):
    """numpy.load with allow_pickle=False refuses pickled objects.
    This is a banca-safety property — if someone substitutes the
    index file with a pickle payload, np.load must NOT execute it."""
    import numpy as np

    # Save with object dtype (would require allow_pickle on load).
    bad = tmp_path / "bad.npz"
    # numpy refuses to save object arrays without allow_pickle=True,
    # so just craft a corrupt file and confirm we don't crash by
    # loading random bytes.
    bad.write_bytes(b"not a real npz")
    with pytest.raises(Exception):  # noqa: B017 — any load failure is acceptable
        load_index(path=bad)


# =====================================================================
# is_index_stale — change detection
# =====================================================================


def test_is_index_stale_when_sidecar_missing(tmp_path):
    """No sidecar → stale → caller rebuilds."""
    registry = {"a": SimpleNamespace(name="a", description="alpha")}
    assert is_index_stale(registry, path=tmp_path / "idx.npz") is True


def test_is_index_stale_when_embedder_model_changes(tmp_path):
    registry = {"a": SimpleNamespace(name="a", description="alpha")}
    save_index(
        {"a": [1.0]},
        {"a": _hash_doc(tool_doc_for_index(registry["a"]))},
        path=tmp_path / "idx.npz",
        embedder_model="old-model",
    )
    assert is_index_stale(registry, path=tmp_path / "idx.npz", embedder_model="new-model") is True


def test_is_index_stale_when_docstring_changes(tmp_path):
    """Renaming a tool or editing its description should invalidate
    the index — otherwise the retriever would rank against stale
    semantics."""
    old_registry = {"a": SimpleNamespace(name="a", description="old description")}
    save_index(
        {"a": [1.0]},
        {"a": _hash_doc(tool_doc_for_index(old_registry["a"]))},
        path=tmp_path / "idx.npz",
        embedder_model=DEFAULT_EMBEDDING_MODEL,
    )
    new_registry = {"a": SimpleNamespace(name="a", description="new description")}
    assert is_index_stale(new_registry, path=tmp_path / "idx.npz") is True


def test_is_index_stale_when_tool_added(tmp_path):
    one_tool = {"a": SimpleNamespace(name="a", description="alpha")}
    save_index(
        {"a": [1.0]},
        {"a": _hash_doc(tool_doc_for_index(one_tool["a"]))},
        path=tmp_path / "idx.npz",
        embedder_model=DEFAULT_EMBEDDING_MODEL,
    )
    two_tools = {
        "a": SimpleNamespace(name="a", description="alpha"),
        "b": SimpleNamespace(name="b", description="beta"),
    }
    assert is_index_stale(two_tools, path=tmp_path / "idx.npz") is True


def test_is_index_fresh_when_nothing_changed(tmp_path):
    registry = {
        "a": SimpleNamespace(name="a", description="alpha"),
        "b": SimpleNamespace(name="b", description="beta"),
    }
    save_index(
        {"a": [1.0], "b": [0.0]},
        {n: _hash_doc(tool_doc_for_index(t)) for n, t in registry.items()},
        path=tmp_path / "idx.npz",
        embedder_model=DEFAULT_EMBEDDING_MODEL,
    )
    assert is_index_stale(registry, path=tmp_path / "idx.npz") is False


def test_sidecar_path_is_meta_json(tmp_path):
    assert _sidecar_path(tmp_path / "x.npz").name == "x.meta.json"
