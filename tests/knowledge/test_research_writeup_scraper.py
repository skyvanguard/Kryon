"""Tests for ResearchWriteupScraper (F4.2).

All tests are offline — we patch ``requests.get`` so we never hit the
real feeds during CI. The fixtures below are handwritten minimal RSS
2.0 and Atom documents that exercise every field the scraper reads.
"""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock, patch

import pytest

try:
    _mod = importlib.import_module("kryon.knowledge.scrapers.research_writeup_scraper")
    ResearchWriteupScraper = _mod.ResearchWriteupScraper
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


_RSS_P0 = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Project Zero</title>
    <item>
      <title>Attacking the Linux kernel via CVE-2023-12345</title>
      <link>https://googleprojectzero.blogspot.com/2023/11/linux-kernel-rce.html</link>
      <description>&lt;p&gt;A detailed look at a recent Linux kernel vulnerability
        (CWE-416 use-after-free, CVE-2023-12345).&lt;/p&gt;</description>
      <pubDate>Mon, 06 Nov 2023 10:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Research methodology notes</title>
      <link>https://googleprojectzero.blogspot.com/2023/10/notes.html</link>
      <description>General notes on fuzzing harness design.</description>
      <pubDate>Tue, 10 Oct 2023 08:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

_ATOM_TOB = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Trail of Bits Blog</title>
  <entry>
    <title>Auditing cryptographic libraries - CVE-2022-99999 case study</title>
    <link href="https://blog.trailofbits.com/2022/07/audit.html" />
    <summary>Our review uncovered a CWE-327 weak-algorithm issue.</summary>
    <updated>2022-07-15T12:00:00Z</updated>
  </entry>
</feed>
"""

_RSS_GHSL = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>GitHub Blog - Security</title>
    <item>
      <title>Supply chain findings in popular npm packages</title>
      <link>https://github.blog/security/supply-chain-2024.html</link>
      <description>Several packages had malicious postinstall scripts.</description>
      <pubDate>Fri, 05 Jan 2024 09:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""


def _mock_response(body: bytes) -> MagicMock:
    resp = MagicMock()
    resp.content = body
    resp.raise_for_status = MagicMock()
    return resp


def test_parse_rss_extracts_title_link_and_cve_cwe():
    scraper = ResearchWriteupScraper()
    items = scraper._parse_feed(  # type: ignore[attr-defined]
        _RSS_P0,
        "project-zero",
        {"url": "x", "label": "Project Zero", "slug": "p0"},
        max_items=10,
    )

    assert len(items) == 2
    first = items[0]
    assert "Attacking the Linux kernel" in first["content"]
    assert first["metadata"]["source"] == "research-writeups"
    assert first["metadata"]["subsource"] == "project-zero"
    assert first["metadata"]["subsource_slug"] == "p0"
    assert first["metadata"]["url"].startswith("https://googleprojectzero.blogspot.com/")
    assert "CWE-416" in first["metadata"]["cwe_ids"]
    assert "CVE-2023-12345" in first["metadata"]["cve_ids"]
    # Second item has no CVE/CWE in text → empty lists
    assert items[1]["metadata"]["cwe_ids"] == []
    assert items[1]["metadata"]["cve_ids"] == []


def test_parse_atom_extracts_entry_fields():
    scraper = ResearchWriteupScraper()
    items = scraper._parse_feed(  # type: ignore[attr-defined]
        _ATOM_TOB,
        "trail-of-bits",
        {"url": "x", "label": "Trail of Bits", "slug": "tob"},
        max_items=10,
    )

    assert len(items) == 1
    item = items[0]
    assert "Auditing cryptographic" in item["content"]
    assert "CWE-327" in item["metadata"]["cwe_ids"]
    assert "CVE-2022-99999" in item["metadata"]["cve_ids"]
    assert item["metadata"]["subsource_slug"] == "tob"


def test_scrape_all_sources_stops_on_network_error():
    """A single failing source should not kill the run."""
    scraper = ResearchWriteupScraper()

    def fake_get(url, **_):
        if "googleprojectzero" in url:
            return _mock_response(_RSS_P0)
        if "trailofbits" in url:
            raise RuntimeError("feed down")
        return _mock_response(_RSS_GHSL)

    with (
        patch("requests.get", side_effect=fake_get),
        patch.object(ResearchWriteupScraper, "rate_limit", return_value=None),
    ):
        items = scraper.scrape(max_per_source=5)

    subsources = {item["metadata"]["subsource"] for item in items}
    assert "project-zero" in subsources
    assert "github-security-lab" in subsources
    assert "trail-of-bits" not in subsources  # failed but did not abort
    # Error was logged, not raised
    assert any("trail-of-bits" in str(e) for e in scraper.errors)


def test_scrape_honours_sources_arg_and_max_per_source():
    scraper = ResearchWriteupScraper()

    with (
        patch("requests.get", return_value=_mock_response(_RSS_P0)) as m,
        patch.object(ResearchWriteupScraper, "rate_limit", return_value=None),
    ):
        items = scraper.scrape(sources=["project-zero"], max_per_source=1)

    assert m.call_count == 1  # only one feed fetched
    assert len(items) == 1  # capped at max_per_source


def test_unknown_source_is_logged_not_raised():
    scraper = ResearchWriteupScraper()
    items = scraper.scrape(sources=["not-a-real-source"])
    assert items == []
    assert any("not-a-real-source" in str(e) for e in scraper.errors)


def test_malformed_feed_does_not_raise():
    scraper = ResearchWriteupScraper()
    items = scraper._parse_feed(  # type: ignore[attr-defined]
        b"<not-xml>>>",
        "project-zero",
        {"url": "x", "label": "Project Zero", "slug": "p0"},
        max_items=10,
    )
    assert items == []
    assert any("parse error" in str(e) for e in scraper.errors)


def test_source_name_matches_registry_key():
    """Registry key and get_source_name() must agree."""
    from kryon.knowledge.scrapers import SCRAPER_REGISTRY

    scraper = SCRAPER_REGISTRY["research-writeups"]()
    assert scraper.get_source_name() == "research-writeups"
