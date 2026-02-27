"""Tests for CWEScraper — MITRE CWE data."""

import importlib
from unittest.mock import MagicMock, patch

import pytest

try:
    _mod = importlib.import_module("kryon.knowledge.scrapers.cwe_scraper")
    CWEScraper = _mod.CWEScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


_FAKE_CWE_RESPONSE = {
    "Weakness": {
        "Name": "Improper Input Validation",
        "Description": "The product does not validate input properly.",
        "Extended_Description": "Extended explanation of input validation issues.",
        "Common_Consequences": [
            {"Scope": "Integrity", "Impact": "Modify data"},
            {"Scope": "Availability", "Impact": "DoS"},
        ],
        "Potential_Mitigations": [
            {"Phase": "Implementation", "Description": "Validate all input"},
        ],
    }
}


def test_source_name():
    scraper = CWEScraper()
    assert scraper.get_source_name() == "cwe"


@patch("kryon.knowledge.scrapers.cwe_scraper.requests.get")
def test_scrape_fetches_cwes(mock_get):
    """Test that scraper fetches CWE data from API."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_CWE_RESPONSE
    mock_get.return_value = resp

    scraper = CWEScraper()
    items = scraper.scrape(cwe_ids=[20, 79], max_results=2)

    assert len(items) == 2
    for item in items:
        assert "content" in item
        assert item["metadata"]["source"] == "cwe"
        assert item["metadata"]["type"] == "weakness"
        assert "CWE-" in item["metadata"]["cwe_id"]


@patch("kryon.knowledge.scrapers.cwe_scraper.requests.get")
def test_scrape_formats_content(mock_get):
    """Verify content includes description, consequences, and mitigations."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_CWE_RESPONSE
    mock_get.return_value = resp

    scraper = CWEScraper()
    items = scraper.scrape(cwe_ids=[20], max_results=1)

    content = items[0]["content"]
    assert "CWE-20" in content
    assert "Improper Input Validation" in content
    assert "Consequences" in content
    assert "Mitigations" in content


@patch("kryon.knowledge.scrapers.cwe_scraper.requests.get")
def test_scrape_fallback_on_api_failure(mock_get):
    """When API returns non-200, use fallback entry."""
    resp = MagicMock()
    resp.status_code = 500
    mock_get.return_value = resp

    scraper = CWEScraper()
    items = scraper.scrape(cwe_ids=[79], max_results=1)

    assert len(items) == 1
    assert "CWE-79" in items[0]["content"]
    assert items[0]["metadata"]["cwe_id"] == "CWE-79"


@patch("kryon.knowledge.scrapers.cwe_scraper.requests.get")
def test_scrape_handles_network_error(mock_get):
    """Network errors should fall back gracefully."""
    mock_get.side_effect = Exception("Connection refused")

    scraper = CWEScraper()
    items = scraper.scrape(cwe_ids=[89], max_results=1)

    # Should get fallback entry
    assert len(items) == 1
    assert "CWE-89" in items[0]["content"]


@patch("kryon.knowledge.scrapers.cwe_scraper.requests.get")
def test_scrape_deduplicates(mock_get):
    """Duplicate CWE IDs should be deduplicated."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_CWE_RESPONSE
    mock_get.return_value = resp

    scraper = CWEScraper()
    # Same CWE ID twice — deduplicate at input level
    items = scraper.scrape(cwe_ids=[20, 20], max_results=5)
    # dict.fromkeys dedup means only 1 fetch
    assert len(items) == 1


@patch("kryon.knowledge.scrapers.cwe_scraper.requests.get")
def test_scrape_respects_max_results(mock_get):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_CWE_RESPONSE
    mock_get.return_value = resp

    scraper = CWEScraper()
    items = scraper.scrape(max_results=3)
    assert len(items) <= 3
