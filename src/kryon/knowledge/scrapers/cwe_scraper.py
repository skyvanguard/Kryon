"""
CWE Scraper
===========

Scrape MITRE Common Weakness Enumeration data for RAG knowledge base.
"""

import logging
import time
from typing import Any

import requests

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

# CWE Top 25 (2023) IDs
_CWE_TOP_25 = [
    787, 79, 89, 416, 78, 20, 125, 22, 352, 434,
    862, 476, 287, 190, 502, 77, 119, 798, 918, 306,
    362, 269, 94, 863, 276,
]

# Additional high-impact CWEs commonly referenced in CVEs
_CWE_EXTRA = [
    611, 918, 1321, 400, 601, 843, 295, 327, 330, 384,
    427, 532, 538, 639, 704, 732, 770, 776, 912, 943,
    1236, 1275, 200, 209, 311, 312, 319,
]

_CWE_API_URL = "https://cweapi.mitre.org/api/v1/cwe/weakness"


class CWEScraper(BaseScraper):
    """
    Scrape CWE weakness descriptions from MITRE.

    Uses the CWE REST API for individual weakness lookups.
    Falls back to curated static descriptions if the API is unavailable.
    """

    def __init__(self):
        super().__init__()
        self.source_name = "cwe"

    def get_source_name(self) -> str:
        return self.source_name

    def scrape(
        self,
        cwe_ids: list[int] | None = None,
        max_results: int = 60,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Scrape CWE data.

        Args:
            cwe_ids: Specific CWE IDs to fetch. Defaults to Top 25 + extras.
            max_results: Maximum items to return.

        Returns:
            List of knowledge items.
        """
        self.last_scrape_time = time.time()

        if cwe_ids is None:
            cwe_ids = list(dict.fromkeys(_CWE_TOP_25 + _CWE_EXTRA))

        items: list[dict[str, Any]] = []
        for cwe_id in cwe_ids[:max_results]:
            try:
                item = self._fetch_cwe(cwe_id)
                if item:
                    items.append(item)
                self.rate_limit(0.3)
            except Exception as e:
                self.log_error(f"Error fetching CWE-{cwe_id}: {e}")

        items = self.deduplicate(items)
        self.scraped_count = len(items)
        return items

    def _fetch_cwe(self, cwe_id: int) -> dict[str, Any] | None:
        """Fetch a single CWE from the API."""
        try:
            resp = requests.get(
                f"{_CWE_API_URL}/{cwe_id}",
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if resp.status_code != 200:
                return self._fallback_cwe(cwe_id)

            data = resp.json()
            weakness = data.get("Weakness", data) if isinstance(data, dict) else data

            name = weakness.get("Name", f"CWE-{cwe_id}")
            description = weakness.get("Description", "")
            extended = weakness.get("Extended_Description", "")
            consequences = weakness.get("Common_Consequences", [])
            mitigations = weakness.get("Potential_Mitigations", [])

            content = self._format_cwe(cwe_id, name, description, extended, consequences, mitigations)
            return {
                "content": content,
                "metadata": {
                    "source": self.source_name,
                    "category": "weakness",
                    "cwe_id": f"CWE-{cwe_id}",
                    "type": "weakness",
                },
            }
        except Exception:
            return self._fallback_cwe(cwe_id)

    def _format_cwe(
        self,
        cwe_id: int,
        name: str,
        description: str,
        extended: str,
        consequences: list,
        mitigations: list,
    ) -> str:
        """Format CWE data as markdown content."""
        parts = [
            f"## CWE-{cwe_id}: {name}",
            "",
            "### Description",
            description,
        ]

        if extended:
            parts += ["", "### Extended Description", extended]

        if consequences:
            parts += ["", "### Consequences"]
            for c in consequences[:5]:
                if isinstance(c, dict):
                    scope = c.get("Scope", "")
                    impact = c.get("Impact", "")
                    parts.append(f"- **{scope}:** {impact}")
                elif isinstance(c, str):
                    parts.append(f"- {c}")

        if mitigations:
            parts += ["", "### Mitigations"]
            for m in mitigations[:5]:
                if isinstance(m, dict):
                    phase = m.get("Phase", "")
                    desc = m.get("Description", "")
                    parts.append(f"- **{phase}:** {desc}")
                elif isinstance(m, str):
                    parts.append(f"- {m}")

        return "\n".join(parts)

    def _fallback_cwe(self, cwe_id: int) -> dict[str, Any] | None:
        """Return a minimal entry when API is unavailable."""
        return {
            "content": f"## CWE-{cwe_id}\n\nCommon Weakness Enumeration entry {cwe_id}. "
            f"Visit https://cwe.mitre.org/data/definitions/{cwe_id}.html for details.",
            "metadata": {
                "source": self.source_name,
                "category": "weakness",
                "cwe_id": f"CWE-{cwe_id}",
                "type": "weakness",
            },
        }
