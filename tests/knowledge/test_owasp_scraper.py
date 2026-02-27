"""Tests for OWASPScraper — OWASP Cheat Sheet Series."""

import importlib
from unittest.mock import MagicMock, patch

import pytest

try:
    _mod = importlib.import_module("kryon.knowledge.scrapers.owasp_scraper")
    OWASPScraper = _mod.OWASPScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


_FAKE_INDEX = """# OWASP Cheat Sheets

- [SQL Injection Prevention](cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md)
- [XSS Prevention](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [Authentication](cheatsheets/Authentication_Cheat_Sheet.md)
"""

_FAKE_SHEET = """# SQL Injection Prevention Cheat Sheet

## Introduction

SQL Injection is a common attack vector...

## Defense Option 1: Prepared Statements

Use parameterized queries to prevent SQL injection.
"""


def test_source_name():
    scraper = OWASPScraper()
    assert scraper.get_source_name() == "owasp"


@patch("kryon.knowledge.scrapers.owasp_scraper.requests.get")
def test_scrape_fetches_sheets(mock_get):
    """Test that scraper fetches index then individual sheets."""
    index_resp = MagicMock()
    index_resp.status_code = 200
    index_resp.text = _FAKE_INDEX

    # Each sheet must have unique content to survive deduplication
    def make_sheet(name):
        r = MagicMock()
        r.status_code = 200
        r.text = f"# {name} Cheat Sheet\n\nUnique content for {name}."
        return r

    mock_get.side_effect = [
        index_resp,
        make_sheet("SQL Injection"),
        make_sheet("XSS Prevention"),
        make_sheet("Authentication"),
    ]

    scraper = OWASPScraper()
    items = scraper.scrape(max_results=3)

    assert len(items) == 3
    for item in items:
        assert "content" in item
        assert item["metadata"]["source"] == "owasp"
        assert item["metadata"]["type"] == "cheatsheet"


@patch("kryon.knowledge.scrapers.owasp_scraper.requests.get")
def test_scrape_handles_index_failure(mock_get):
    """Scraper should return empty list when index fetch fails."""
    resp = MagicMock()
    resp.status_code = 500
    mock_get.return_value = resp

    scraper = OWASPScraper()
    items = scraper.scrape()
    assert items == []


@patch("kryon.knowledge.scrapers.owasp_scraper.requests.get")
def test_scrape_handles_sheet_failure(mock_get):
    """Failed sheet fetches should be skipped, not crash."""
    index_resp = MagicMock()
    index_resp.status_code = 200
    index_resp.text = _FAKE_INDEX

    ok_resp1 = MagicMock()
    ok_resp1.status_code = 200
    ok_resp1.text = "Unique content sheet 1"

    ok_resp2 = MagicMock()
    ok_resp2.status_code = 200
    ok_resp2.text = "Unique content sheet 2"

    fail_resp = MagicMock()
    fail_resp.status_code = 404

    mock_get.side_effect = [index_resp, ok_resp1, fail_resp, ok_resp2]

    scraper = OWASPScraper()
    items = scraper.scrape(max_results=3)
    assert len(items) == 2  # One 404'd sheet was skipped


@patch("kryon.knowledge.scrapers.owasp_scraper.requests.get")
def test_scrape_truncates_long_content(mock_get):
    """Very long sheets should be truncated."""
    index_resp = MagicMock()
    index_resp.status_code = 200
    index_resp.text = "- [Big](cheatsheets/Big_Cheat_Sheet.md)\n"

    long_resp = MagicMock()
    long_resp.status_code = 200
    long_resp.text = "A" * 10000

    mock_get.side_effect = [index_resp, long_resp]

    scraper = OWASPScraper()
    items = scraper.scrape(max_results=1)
    assert len(items) == 1
    assert len(items[0]["content"]) < 9000
    assert "[Truncated]" in items[0]["content"]


@patch("kryon.knowledge.scrapers.owasp_scraper.requests.get")
def test_scrape_deduplicates(mock_get):
    """Duplicate sheets should be deduplicated."""
    index_resp = MagicMock()
    index_resp.status_code = 200
    # Same sheet name appears twice
    index_resp.text = (
        "- [SQL](cheatsheets/SQL_Cheat_Sheet.md)\n"
        "- [SQL Again](cheatsheets/SQL_Cheat_Sheet.md)\n"
    )

    sheet_resp = MagicMock()
    sheet_resp.status_code = 200
    sheet_resp.text = _FAKE_SHEET

    mock_get.side_effect = [index_resp, sheet_resp]

    scraper = OWASPScraper()
    items = scraper.scrape()
    # Index deduplication means only one fetch
    assert len(items) == 1
