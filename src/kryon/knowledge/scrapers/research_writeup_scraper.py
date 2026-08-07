"""Research Writeup Scraper — F4.2.

Pulls high-signal vulnerability research writeups from three primary
industry sources via their public RSS / Atom feeds:

- Project Zero (Google): googleprojectzero.blogspot.com
- Trail of Bits: blog.trailofbits.com
- GitHub Security Lab: github.blog/category/security/

Each entry is normalized to the standard ``{content, metadata}`` shape
the RAG pipeline consumes. We deliberately avoid heavy HTML scraping —
RSS entries expose enough summary + link to be useful as retrieval
context, and the user can always follow the URL for the full post.

The three sources can be fetched independently via the ``sources``
argument, which is useful both for testing and for the auto-updater
(each source has its own rate-limit budget).
"""

from __future__ import annotations

import logging
import re
import time
from html import unescape
from typing import Any
from xml.etree import ElementTree as ET

import requests

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

# RSS / Atom endpoints. Each has been verified to expose public feeds.
_FEEDS: dict[str, dict[str, str]] = {
    "project-zero": {
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
        "label": "Project Zero",
        "slug": "p0",
    },
    "trail-of-bits": {
        "url": "https://blog.trailofbits.com/feed/",
        "label": "Trail of Bits",
        "slug": "tob",
    },
    "github-security-lab": {
        # GitHub's main blog security category also covers GHSL advisories.
        "url": "https://github.blog/category/security/feed/",
        "label": "GitHub Security Lab",
        "slug": "ghsl",
    },
}

# Extract CWE / CVE identifiers from summary text for metadata enrichment.
_CWE_RE = re.compile(r"CWE-\d{1,4}", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# RSS/Atom namespaces we care about.
_ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html_text: str) -> str:
    """Remove HTML tags and collapse whitespace for plain-text summary."""
    text = _HTML_TAG_RE.sub(" ", html_text)
    text = unescape(text)
    return " ".join(text.split())


class ResearchWriteupScraper(BaseScraper):
    """Aggregator for vulnerability-research blog feeds.

    Unlike :class:`WriteupScraper` (CTF-oriented), this scraper targets
    primary-source industry research writeups where the authors are the
    people who discovered the bug. Output feeds into the RAG corpus so
    hunter agents can recall similar methodologies and patterns.
    """

    def __init__(self, timeout: int = 15):
        super().__init__()
        self._timeout = timeout
        self.source_name = "research-writeups"

    def get_source_name(self) -> str:
        return self.source_name

    def scrape(
        self,
        sources: list[str] | None = None,
        max_per_source: int = 25,
        **_: Any,
    ) -> list[dict[str, Any]]:
        """Fetch and normalize research writeups.

        Args:
            sources: Subset of :data:`_FEEDS` keys to scrape.
                Defaults to all three.
            max_per_source: Per-feed cap. Total items is at most
                ``max_per_source * len(sources)``.
        """
        self.last_scrape_time = time.time()

        if not sources:
            sources = list(_FEEDS.keys())

        items: list[dict[str, Any]] = []
        for src in sources:
            if src not in _FEEDS:
                self.log_error(f"Unknown research source: {src}")
                continue
            try:
                items.extend(self._scrape_feed(src, max_per_source))
                self.rate_limit(2)
            except Exception as e:
                self.log_error(f"Error scraping {src}: {e}")

        items = self.deduplicate(items)
        self.scraped_count = len(items)
        return items

    def _scrape_feed(self, source: str, max_items: int) -> list[dict[str, Any]]:
        """Fetch a single RSS/Atom feed and normalize its entries."""
        cfg = _FEEDS[source]
        response = requests.get(
            cfg["url"],
            timeout=self._timeout,
            headers={"User-Agent": "kryon-research-writeup-scraper/1.0"},
        )
        response.raise_for_status()
        return self._parse_feed(response.content, source, cfg, max_items)

    def _parse_feed(
        self,
        raw: bytes,
        source: str,
        cfg: dict[str, str],
        max_items: int,
    ) -> list[dict[str, Any]]:
        """Parse RSS 2.0 or Atom and emit normalized knowledge items."""
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            self.log_error(f"{source}: feed parse error: {e}")
            return []

        tag = root.tag.lower()
        # RSS 2.0 → <rss><channel><item>
        if tag.endswith("rss"):
            entries = root.findall("./channel/item")
            parser = self._parse_rss_item
        # Atom → <feed><entry>
        elif tag.endswith("feed"):
            entries = root.findall("atom:entry", _ATOM_NS)
            parser = self._parse_atom_entry
        else:
            self.log_error(f"{source}: unknown feed root tag {tag!r}")
            return []

        items: list[dict[str, Any]] = []
        for entry in entries[:max_items]:
            try:
                item = parser(entry, source, cfg)
                if item:
                    items.append(item)
            except Exception as e:
                self.log_error(f"{source}: entry parse error: {e}")

        return items

    def _parse_rss_item(
        self,
        entry: ET.Element,
        source: str,
        cfg: dict[str, str],
    ) -> dict[str, Any] | None:
        title = (entry.findtext("title") or "").strip()
        link = (entry.findtext("link") or "").strip()
        description = entry.findtext("description") or ""
        pub_date = (entry.findtext("pubDate") or "").strip()

        if not title or not link:
            return None

        summary = _strip_html(description)
        return self._build_item(source, cfg, title, link, summary, pub_date)

    def _parse_atom_entry(
        self,
        entry: ET.Element,
        source: str,
        cfg: dict[str, str],
    ) -> dict[str, Any] | None:
        title = (entry.findtext("atom:title", default="", namespaces=_ATOM_NS) or "").strip()
        link_elem = entry.find("atom:link", _ATOM_NS)
        link = link_elem.get("href", "").strip() if link_elem is not None else ""
        summary_text = (
            entry.findtext("atom:summary", default="", namespaces=_ATOM_NS)
            or entry.findtext("atom:content", default="", namespaces=_ATOM_NS)
            or ""
        )
        pub_date = (entry.findtext("atom:updated", default="", namespaces=_ATOM_NS) or "").strip()

        if not title or not link:
            return None

        summary = _strip_html(summary_text)
        return self._build_item(source, cfg, title, link, summary, pub_date)

    def _build_item(
        self,
        source: str,
        cfg: dict[str, str],
        title: str,
        link: str,
        summary: str,
        pub_date: str,
    ) -> dict[str, Any]:
        # Truncate very long summaries — full post lives behind the URL.
        if len(summary) > 2000:
            summary = summary[:2000].rsplit(" ", 1)[0] + "…"

        haystack = f"{title} {summary}"
        cwe_ids = sorted({m.upper() for m in _CWE_RE.findall(haystack)})
        cve_ids = sorted({m.upper() for m in _CVE_RE.findall(haystack)})

        content = (
            f"**{cfg['label']}: {title}**\n\n"
            f"{summary}\n\n"
            f"**Source:** {cfg['label']}\n"
            f"**Published:** {pub_date or 'unknown'}\n"
            f"**URL:** {link}\n"
        )
        if cwe_ids:
            content += f"**CWE:** {', '.join(cwe_ids)}\n"
        if cve_ids:
            content += f"**CVE:** {', '.join(cve_ids)}\n"

        metadata = {
            "source": self.source_name,
            "subsource": source,
            "subsource_slug": cfg["slug"],
            "title": title,
            "url": link,
            "published": pub_date,
            "type": "research-writeup",
            "cwe_ids": cwe_ids,
            "cve_ids": cve_ids,
            "timestamp": time.time(),
        }
        return {"content": content, "metadata": metadata}


def scrape_research_writeups(**kwargs: Any) -> list[dict[str, Any]]:
    """Convenience wrapper — instantiate and scrape."""
    scraper = ResearchWriteupScraper()
    return scraper.scrape(**kwargs)
