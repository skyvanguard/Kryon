"""
OWASP Scraper
=============

Scrape OWASP Cheat Sheet Series from GitHub for RAG knowledge base.
"""

import logging
import time
from typing import Any, Optional

import requests

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

_INDEX_URL = (
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/Index.md"
)
_RAW_BASE = (
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/"
)


class OWASPScraper(BaseScraper):
    """
    Scrape OWASP Cheat Sheet Series from GitHub.

    Downloads the index of cheat sheets and fetches each one as raw markdown.
    """

    def __init__(self):
        super().__init__()
        self.source_name = "owasp"

    def get_source_name(self) -> str:
        return self.source_name

    def scrape(
        self,
        max_results: int = 80,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Scrape OWASP cheat sheets.

        Args:
            max_results: Maximum number of cheat sheets to fetch.

        Returns:
            List of knowledge items.
        """
        self.last_scrape_time = time.time()

        sheet_names = self._fetch_index()
        if not sheet_names:
            return []

        items: list[dict[str, Any]] = []
        for name in sheet_names[:max_results]:
            try:
                content = self._fetch_sheet(name)
                if not content:
                    continue

                # Truncate very long sheets for RAG efficiency
                if len(content) > 8000:
                    content = content[:8000] + "\n\n[Truncated]"

                items.append({
                    "content": content,
                    "metadata": {
                        "source": self.source_name,
                        "category": "web-security",
                        "sheet_name": name,
                        "type": "cheatsheet",
                    },
                })
                self.rate_limit(0.5)
            except Exception as e:
                self.log_error(f"Error fetching sheet '{name}': {e}")

        items = self.deduplicate(items)
        self.scraped_count = len(items)
        return items

    def _fetch_index(self) -> list[str]:
        """Fetch the cheat sheet index and extract sheet filenames."""
        try:
            resp = requests.get(_INDEX_URL, timeout=30)
            if resp.status_code != 200:
                self.log_error(f"OWASP index fetch failed: HTTP {resp.status_code}")
                return []

            names: list[str] = []
            for line in resp.text.splitlines():
                # Lines like: - [Sheet Name](cheatsheets/Sheet_Name_Cheat_Sheet.md)
                if "cheatsheets/" in line and ".md" in line:
                    start = line.index("cheatsheets/") + len("cheatsheets/")
                    end = line.index(".md", start) + 3
                    names.append(line[start:end])
                elif "_Cheat_Sheet.md" in line and "](" in line:
                    # Alternative format: [Name](Sheet_Name_Cheat_Sheet.md)
                    start = line.index("](") + 2
                    end = line.index(".md", start) + 3
                    filename = line[start:end].strip()
                    if filename and not filename.startswith("http"):
                        names.append(filename)

            return list(dict.fromkeys(names))  # deduplicate preserving order
        except Exception as e:
            self.log_error(f"Error fetching OWASP index: {e}")
            return []

    def _fetch_sheet(self, filename: str) -> Optional[str]:
        """Fetch a single cheat sheet by filename."""
        url = f"{_RAW_BASE}{filename}"
        try:
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                return resp.text
            return None
        except Exception:
            return None
