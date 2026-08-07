"""Tests for StaticSeedScraper — loading JSON seed data."""

import importlib
import json
import tempfile
from pathlib import Path

import pytest

try:
    _mod = importlib.import_module("kryon.knowledge.scrapers.static_seed_scraper")
    StaticSeedScraper = _mod.StaticSeedScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


@pytest.fixture
def seed_dir(tmp_path):
    """Create a temporary seed data directory with sample JSON files."""
    data = [
        {
            "id": "test-001",
            "content": "## Test Document 1\n\nThis is a test.",
            "metadata": {"source": "test-source", "category": "testing"},
        },
        {
            "id": "test-002",
            "content": "## Test Document 2\n\nAnother test document.",
            "metadata": {"source": "test-source", "category": "testing"},
        },
    ]
    (tmp_path / "test_data.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


@pytest.fixture
def seed_dir_multiple(tmp_path):
    """Create a seed directory with multiple JSON files."""
    file_a = [
        {"id": "a1", "content": "Content A1", "metadata": {"source": "file-a"}},
        {"id": "a2", "content": "Content A2", "metadata": {"source": "file-a"}},
    ]
    file_b = [
        {"id": "b1", "content": "Content B1", "metadata": {"source": "file-b"}},
    ]
    (tmp_path / "a.json").write_text(json.dumps(file_a), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(file_b), encoding="utf-8")
    return tmp_path


def test_source_name():
    scraper = StaticSeedScraper()
    assert scraper.get_source_name() == "static-seed"


def test_loads_json_files(seed_dir):
    scraper = StaticSeedScraper(seed_dir=seed_dir)
    items = scraper.scrape()
    assert len(items) == 2
    assert items[0]["content"] == "## Test Document 1\n\nThis is a test."
    assert items[0]["metadata"]["source"] == "test-source"
    assert items[1]["metadata"]["category"] == "testing"


def test_loads_multiple_files(seed_dir_multiple):
    scraper = StaticSeedScraper(seed_dir=seed_dir_multiple)
    items = scraper.scrape()
    assert len(items) == 3
    sources = {item["metadata"]["source"] for item in items}
    assert sources == {"file-a", "file-b"}


def test_deduplication(tmp_path):
    """Duplicate content entries should be deduplicated."""
    data = [
        {"id": "dup1", "content": "Same content", "metadata": {"source": "test"}},
        {"id": "dup2", "content": "Same content", "metadata": {"source": "test"}},
        {"id": "dup3", "content": "Different content", "metadata": {"source": "test"}},
    ]
    (tmp_path / "dups.json").write_text(json.dumps(data), encoding="utf-8")

    scraper = StaticSeedScraper(seed_dir=tmp_path)
    items = scraper.scrape()
    assert len(items) == 2


def test_metadata_preserved(seed_dir):
    scraper = StaticSeedScraper(seed_dir=seed_dir)
    items = scraper.scrape()
    for item in items:
        assert "source" in item["metadata"]
        assert "category" in item["metadata"]


def test_invalid_json_handled(tmp_path):
    """Invalid JSON files should log an error but not crash."""
    (tmp_path / "valid.json").write_text(
        json.dumps([{"id": "v1", "content": "Valid", "metadata": {}}]),
        encoding="utf-8",
    )
    (tmp_path / "invalid.json").write_text("NOT JSON {{{", encoding="utf-8")

    scraper = StaticSeedScraper(seed_dir=tmp_path)
    items = scraper.scrape()
    assert len(items) == 1
    assert len(scraper.errors) == 1


def test_non_array_json_handled(tmp_path):
    """JSON files that aren't arrays should log an error."""
    (tmp_path / "object.json").write_text(json.dumps({"key": "value"}), encoding="utf-8")

    scraper = StaticSeedScraper(seed_dir=tmp_path)
    items = scraper.scrape()
    assert len(items) == 0
    assert len(scraper.errors) == 1


def test_missing_content_skipped(tmp_path):
    """Entries without content should be skipped."""
    data = [
        {"id": "no-content", "metadata": {"source": "test"}},
        {"id": "empty-content", "content": "", "metadata": {"source": "test"}},
        {"id": "valid", "content": "Has content", "metadata": {"source": "test"}},
    ]
    (tmp_path / "data.json").write_text(json.dumps(data), encoding="utf-8")

    scraper = StaticSeedScraper(seed_dir=tmp_path)
    items = scraper.scrape()
    assert len(items) == 1
    assert items[0]["content"] == "Has content"


def test_missing_directory():
    """Non-existent directory should return empty list."""
    scraper = StaticSeedScraper(seed_dir="/nonexistent/path/xyz123")
    items = scraper.scrape()
    assert items == []
    assert len(scraper.errors) == 1


def test_default_source_set(tmp_path):
    """If metadata has no source, it should default to 'static-seed'."""
    data = [{"id": "x", "content": "Hello", "metadata": {}}]
    (tmp_path / "nosource.json").write_text(json.dumps(data), encoding="utf-8")

    scraper = StaticSeedScraper(seed_dir=tmp_path)
    items = scraper.scrape()
    assert items[0]["metadata"]["source"] == "static-seed"


def test_stats(seed_dir):
    scraper = StaticSeedScraper(seed_dir=seed_dir)
    items = scraper.scrape()
    stats = scraper.get_stats()
    assert stats["source"] == "static-seed"
    assert stats["scraped_count"] == 2
    assert stats["last_scrape"] is not None


def test_builtin_seed_data():
    """Test that the built-in seed_data directory loads successfully."""
    scraper = StaticSeedScraper()
    items = scraper.scrape()
    # Should have seed data if the JSON files exist
    if items:
        assert scraper.scraped_count > 0
        for item in items[:5]:
            assert "content" in item
            assert "metadata" in item
            assert isinstance(item["content"], str)
            assert len(item["content"]) > 0
