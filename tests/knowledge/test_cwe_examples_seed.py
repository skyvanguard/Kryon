"""Tests for the cwe_examples.json seed corpus (F4.2).

These validate structural invariants the RAG pipeline and any downstream
consumers rely on: every entry has a CWE id, a canonical content layout,
and parseable metadata.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

try:
    importlib.import_module("kryon.knowledge.scrapers.static_seed_scraper")
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)

_SEED_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "kryon"
    / "knowledge"
    / "seed_data"
    / "cwe_examples.json"
)
_CWE_RE = re.compile(r"^CWE-\d{1,4}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


@pytest.fixture(scope="module")
def entries() -> list[dict]:
    assert _SEED_PATH.is_file(), f"missing seed file: {_SEED_PATH}"
    with _SEED_PATH.open(encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list) and data, "cwe_examples.json must be a non-empty list"
    return data


def test_seed_file_parses_and_has_entries(entries):
    assert len(entries) >= 10, f"expected ≥10 CWE examples, got {len(entries)}"


def test_each_entry_has_required_shape(entries):
    for entry in entries:
        assert "id" in entry and entry["id"], f"missing id: {entry}"
        assert "content" in entry and isinstance(entry["content"], str)
        assert entry["content"].strip(), f"empty content: {entry['id']}"
        assert "metadata" in entry and isinstance(entry["metadata"], dict)


def test_metadata_fields_are_well_formed(entries):
    seen_ids = set()
    for entry in entries:
        m = entry["metadata"]
        assert m.get("source") == "cwe-examples", f"{entry['id']} wrong source"
        assert m.get("type") == "cwe-example", f"{entry['id']} wrong type"
        cwe = m.get("cwe_id")
        assert cwe and _CWE_RE.match(cwe), f"{entry['id']} bad cwe_id {cwe!r}"
        assert "language" in m and m["language"]
        assert m.get("severity") in {"low", "medium", "high", "critical"}, (
            f"{entry['id']} unexpected severity {m.get('severity')!r}"
        )
        if "cve_id" in m:
            assert _CVE_RE.match(m["cve_id"]), f"{entry['id']} bad cve_id {m['cve_id']!r}"
        assert entry["id"] not in seen_ids, f"duplicate id {entry['id']}"
        seen_ids.add(entry["id"])


def test_content_mentions_declared_cwe_id(entries):
    """Content body should mention its own CWE id so RAG retrieval over
    the text alone can surface the right example."""
    for entry in entries:
        cwe = entry["metadata"]["cwe_id"]
        assert cwe in entry["content"], (
            f"{entry['id']}: content does not mention {cwe}"
        )


def test_covers_at_least_ten_distinct_cwes(entries):
    cwes = {e["metadata"]["cwe_id"] for e in entries}
    assert len(cwes) >= 10, f"only {len(cwes)} distinct CWEs covered: {cwes}"


def test_seed_scraper_ingests_cwe_examples():
    """The static-seed scraper must pick up the new file automatically."""
    from kryon.knowledge.scrapers.static_seed_scraper import StaticSeedScraper

    items = StaticSeedScraper().scrape()
    sources = {item["metadata"].get("source") for item in items}
    assert "cwe-examples" in sources, f"cwe-examples not ingested; saw {sources}"
