"""Tests for VendorAdvisoryScraper — CISA KEV + GitHub Advisories."""

import importlib
from unittest.mock import MagicMock, patch

import pytest

try:
    _mod = importlib.import_module("kryon.knowledge.scrapers.vendor_advisory_scraper")
    VendorAdvisoryScraper = _mod.VendorAdvisoryScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


_FAKE_KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "shortDescription": "Remote code execution via JNDI in Log4j.",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply updates.",
            "notes": "",
        },
        {
            "cveID": "CVE-2017-0144",
            "vendorProject": "Microsoft",
            "product": "Windows SMB",
            "vulnerabilityName": "EternalBlue",
            "shortDescription": "SMBv1 RCE vulnerability.",
            "dateAdded": "2017-03-14",
            "dueDate": "2017-04-14",
            "requiredAction": "Apply MS17-010.",
            "notes": "",
        },
    ]
}

_FAKE_GH_ADVISORIES = [
    {
        "ghsa_id": "GHSA-test-1234",
        "summary": "Test vulnerability in test-pkg",
        "description": "A test vulnerability description.",
        "severity": "high",
        "published_at": "2024-01-15",
        "identifiers": [
            {"type": "CVE", "value": "CVE-2024-0001"},
            {"type": "GHSA", "value": "GHSA-test-1234"},
        ],
        "vulnerabilities": [
            {
                "package": {"name": "test-pkg", "ecosystem": "npm"},
                "vulnerable_version_range": "< 2.0.0",
            }
        ],
    }
]


def test_source_name():
    scraper = VendorAdvisoryScraper()
    assert scraper.get_source_name() == "vendor-advisories"


@patch("kryon.knowledge.scrapers.vendor_advisory_scraper.requests.get")
def test_scrape_cisa_kev(mock_get):
    """Test CISA KEV scraping."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_KEV
    mock_get.return_value = resp

    scraper = VendorAdvisoryScraper()
    items = scraper.scrape(sources=["cisa-kev"], max_results=10)

    assert len(items) == 2
    assert "CVE-2021-44228" in items[0]["content"]
    assert items[0]["metadata"]["source"] == "cisa-kev"
    assert items[0]["metadata"]["type"] == "advisory"


@patch("kryon.knowledge.scrapers.vendor_advisory_scraper.requests.get")
def test_scrape_github_advisories(mock_get):
    """Test GitHub Security Advisories scraping."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_GH_ADVISORIES
    mock_get.return_value = resp

    scraper = VendorAdvisoryScraper()
    items = scraper.scrape(sources=["github"], max_results=10)

    assert len(items) == 1
    assert "GHSA-test-1234" in items[0]["content"]
    assert items[0]["metadata"]["source"] == "github-advisory"
    assert items[0]["metadata"]["cve_id"] == "CVE-2024-0001"


@patch("kryon.knowledge.scrapers.vendor_advisory_scraper.requests.get")
def test_scrape_both_sources(mock_get):
    """Test scraping from both sources."""
    kev_resp = MagicMock()
    kev_resp.status_code = 200
    kev_resp.json.return_value = _FAKE_KEV

    gh_resp = MagicMock()
    gh_resp.status_code = 200
    gh_resp.json.return_value = _FAKE_GH_ADVISORIES

    mock_get.side_effect = [kev_resp, gh_resp]

    scraper = VendorAdvisoryScraper()
    items = scraper.scrape(sources=["cisa-kev", "github"], max_results=20)

    assert len(items) == 3
    sources = {item["metadata"]["source"] for item in items}
    assert "cisa-kev" in sources
    assert "github-advisory" in sources


@patch("kryon.knowledge.scrapers.vendor_advisory_scraper.requests.get")
def test_scrape_handles_kev_failure(mock_get):
    """CISA KEV failure should not crash the scraper."""
    resp = MagicMock()
    resp.status_code = 503
    mock_get.return_value = resp

    scraper = VendorAdvisoryScraper()
    items = scraper.scrape(sources=["cisa-kev"])
    assert items == []
    assert len(scraper.errors) >= 1


@patch("kryon.knowledge.scrapers.vendor_advisory_scraper.requests.get")
def test_scrape_handles_github_failure(mock_get):
    """GitHub API failure should not crash the scraper."""
    resp = MagicMock()
    resp.status_code = 403
    mock_get.return_value = resp

    scraper = VendorAdvisoryScraper()
    items = scraper.scrape(sources=["github"])
    assert items == []


@patch("kryon.knowledge.scrapers.vendor_advisory_scraper.requests.get")
def test_kev_content_format(mock_get):
    """Verify KEV content includes expected fields."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _FAKE_KEV
    mock_get.return_value = resp

    scraper = VendorAdvisoryScraper()
    items = scraper.scrape(sources=["cisa-kev"])

    content = items[0]["content"]
    assert "CVE-2021-44228" in content
    assert "Apache" in content
    assert "Log4j" in content
    assert "Required Action" in content
