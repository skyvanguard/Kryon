"""Tests for intelligence scraper integration with RAG knowledge base."""

import importlib
import sys

import pytest

# The knowledge __init__ imports auto_updater which requires `schedule` (RAG dep).
# Import the scraper module directly to avoid that chain.
try:
    _mod = importlib.import_module("kryon.knowledge.scrapers.intelligence_scraper")
    IntelligenceScraper = _mod.IntelligenceScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


def test_scraper_source_name():
    scraper = IntelligenceScraper()
    assert scraper.get_source_name() == "intelligence-feed"


def test_scrape_mitre_techniques():
    scraper = IntelligenceScraper(max_items=200)
    items = scraper._scrape_mitre_techniques()
    # Should have technique entries from local mitre_attack.json
    assert len(items) > 0
    # Each item should have content and metadata
    for item in items[:3]:
        assert "content" in item
        assert "metadata" in item
        assert item["metadata"]["source"] == "mitre-attack"
        assert "technique_id" in item["metadata"]
        assert "MITRE ATT&CK Technique" in item["content"]


def test_scrape_full():
    scraper = IntelligenceScraper(max_items=10)
    items = scraper.scrape()
    # Should at least have MITRE techniques (CISA KEV may not be cached)
    assert len(items) > 0
    assert scraper.scraped_count > 0
    assert scraper.last_scrape_time is not None


def test_scrape_deduplicates():
    scraper = IntelligenceScraper(max_items=200)
    items = scraper.scrape()
    contents = [i["content"] for i in items]
    # No duplicates
    assert len(contents) == len(set(contents))


def test_scrape_max_items():
    scraper = IntelligenceScraper(max_items=5)
    items = scraper.scrape()
    assert len(items) <= 5
