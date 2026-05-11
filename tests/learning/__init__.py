"""Tests for kryon.learning — F77.G self-improving loop foundation.

Pure tests (profiler, chain_extractor) run anywhere. ChromaDB-backed
tests (experiences, findings_library) skip gracefully when chromadb is
not installed via `pytest.importorskip("chromadb")`.
"""
