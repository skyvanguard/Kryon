"""Intelligence feed scraper — feeds enriched CVE/MITRE data into the RAG knowledge base."""

from __future__ import annotations

import logging
import time
from typing import Any

from kryon.knowledge.scrapers.base_scraper import BaseScraper

logger = logging.getLogger(__name__)


class IntelligenceScraper(BaseScraper):
    """Feed enriched CVE/MITRE data into the RAG knowledge base."""

    def __init__(self, max_items: int = 100):
        super().__init__()
        self._max_items = max_items

    def get_source_name(self) -> str:
        return "intelligence-feed"

    def scrape(self, **kwargs) -> list[dict[str, Any]]:
        """Pull from MITRE ATT&CK local data + CISA KEV (cached)."""
        items: list[dict[str, Any]] = []
        self.last_scrape_time = time.time()

        try:
            items.extend(self._scrape_mitre_techniques())
        except Exception as e:
            self.log_error(f"MITRE scrape failed: {e}")

        try:
            items.extend(self._scrape_cisa_kev())
        except Exception as e:
            self.log_error(f"CISA KEV scrape failed: {e}")

        items = self.deduplicate(items)
        self.scraped_count = len(items)
        return items[: self._max_items]

    def _scrape_mitre_techniques(self) -> list[dict[str, Any]]:
        """Extract MITRE ATT&CK technique descriptions for RAG indexing."""
        from kryon.intelligence.mitre import MITREMapper

        mapper = MITREMapper()
        data = mapper._load_data()
        techniques = data.get("techniques", {})

        items = []
        for tid, info in techniques.items():
            content = (
                f"MITRE ATT&CK Technique {tid}: {info.get('name', '')}\n"
                f"Tactic: {info.get('tactic_id', '')}\n"
                f"Description: {info.get('description', '')}\n"
                f"Platforms: {', '.join(info.get('platforms', []))}"
            )
            items.append({
                "content": content,
                "metadata": {
                    "source": "mitre-attack",
                    "technique_id": tid,
                    "tactic_id": info.get("tactic_id", ""),
                    "type": "technique",
                },
            })

        return items

    def _scrape_cisa_kev(self) -> list[dict[str, Any]]:
        """Extract CISA KEV entries (from cache file)."""
        import json
        from pathlib import Path

        cache_path = Path.home() / ".kryon" / "cache" / "cisa_kev.json"
        if not cache_path.exists():
            return []

        with open(cache_path, encoding="utf-8") as f:
            data = json.load(f)

        items = []
        for vuln in data.get("vulnerabilities", [])[:self._max_items]:
            content = (
                f"CISA Known Exploited Vulnerability: {vuln.get('cveID', '')}\n"
                f"Vendor: {vuln.get('vendorProject', '')}\n"
                f"Product: {vuln.get('product', '')}\n"
                f"Description: {vuln.get('shortDescription', '')}\n"
                f"Date Added: {vuln.get('dateAdded', '')}\n"
                f"Required Action: {vuln.get('requiredAction', '')}"
            )
            items.append({
                "content": content,
                "metadata": {
                    "source": "cisa-kev",
                    "cve_id": vuln.get("cveID", ""),
                    "type": "vulnerability",
                },
            })

        return items
