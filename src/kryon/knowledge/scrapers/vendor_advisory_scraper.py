"""
Vendor Advisory Scraper
=======================

Scrape security advisories from CISA KEV and GitHub Security Advisories.
"""

import logging
import os
import time
from typing import Any

import requests

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


class VendorAdvisoryScraper(BaseScraper):
    """
    Scrape security advisories from multiple vendor sources.

    Sources:
    - CISA Known Exploited Vulnerabilities (KEV) catalog
    - GitHub Security Advisories (reviewed)
    """

    def __init__(self):
        super().__init__()
        self.source_name = "vendor-advisories"
        self._github_token = os.getenv("GITHUB_TOKEN")

    def get_source_name(self) -> str:
        return self.source_name

    def scrape(
        self,
        sources: list[str] | None = None,
        max_results: int = 100,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Scrape vendor advisories.

        Args:
            sources: Which sources to use ("cisa-kev", "github").
                     Defaults to both.
            max_results: Maximum items to return.

        Returns:
            List of advisory knowledge items.
        """
        self.last_scrape_time = time.time()

        if sources is None:
            sources = ["cisa-kev", "github"]

        items: list[dict[str, Any]] = []

        if "cisa-kev" in sources:
            try:
                kev_items = self._scrape_cisa_kev(max_results // 2)
                items.extend(kev_items)
            except Exception as e:
                self.log_error(f"CISA KEV scrape failed: {e}")

        if "github" in sources:
            try:
                gh_items = self._scrape_github_advisories(max_results // 2)
                items.extend(gh_items)
            except Exception as e:
                self.log_error(f"GitHub advisories scrape failed: {e}")

        items = self.deduplicate(items)
        self.scraped_count = len(items)
        return items[:max_results]

    def _scrape_cisa_kev(self, max_results: int) -> list[dict[str, Any]]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        resp = requests.get(_CISA_KEV_URL, timeout=30)
        if resp.status_code != 200:
            self.log_error(f"CISA KEV fetch failed: HTTP {resp.status_code}")
            return []

        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        items: list[dict[str, Any]] = []
        for vuln in vulns[:max_results]:
            content = self._format_kev(vuln)
            items.append({
                "content": content,
                "metadata": {
                    "source": "cisa-kev",
                    "category": "advisory",
                    "cve_id": vuln.get("cveID", ""),
                    "vendor": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "type": "advisory",
                },
            })

        return items

    def _format_kev(self, vuln: dict) -> str:
        """Format a CISA KEV entry."""
        return (
            f"## {vuln.get('cveID', 'Unknown')} — {vuln.get('vulnerabilityName', '')}\n\n"
            f"**Vendor:** {vuln.get('vendorProject', '')}\n"
            f"**Product:** {vuln.get('product', '')}\n"
            f"**Date Added:** {vuln.get('dateAdded', '')}\n"
            f"**Due Date:** {vuln.get('dueDate', '')}\n\n"
            f"### Description\n{vuln.get('shortDescription', '')}\n\n"
            f"### Required Action\n{vuln.get('requiredAction', '')}\n\n"
            f"### Notes\n{vuln.get('notes', 'None')}"
        )

    def _scrape_github_advisories(self, max_results: int) -> list[dict[str, Any]]:
        """Fetch reviewed GitHub Security Advisories."""
        headers = {"Accept": "application/vnd.github+json"}
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"

        items: list[dict[str, Any]] = []
        per_page = min(max_results, 100)

        try:
            resp = requests.get(
                _GITHUB_ADVISORIES_URL,
                headers=headers,
                params={"type": "reviewed", "per_page": per_page},
                timeout=30,
            )
            if resp.status_code != 200:
                self.log_error(f"GitHub advisories fetch failed: HTTP {resp.status_code}")
                return []

            advisories = resp.json()
            for adv in advisories[:max_results]:
                content = self._format_github_advisory(adv)
                cve_id = ""
                identifiers = adv.get("identifiers", [])
                for ident in identifiers:
                    if ident.get("type") == "CVE":
                        cve_id = ident.get("value", "")
                        break

                items.append({
                    "content": content,
                    "metadata": {
                        "source": "github-advisory",
                        "category": "advisory",
                        "ghsa_id": adv.get("ghsa_id", ""),
                        "cve_id": cve_id,
                        "severity": adv.get("severity", ""),
                        "type": "advisory",
                    },
                })

        except Exception as e:
            self.log_error(f"GitHub advisories error: {e}")

        return items

    def _format_github_advisory(self, adv: dict) -> str:
        """Format a GitHub Security Advisory."""
        ghsa_id = adv.get("ghsa_id", "Unknown")
        summary = adv.get("summary", "")
        description = adv.get("description", "")
        severity = adv.get("severity", "unknown")
        published = adv.get("published_at", "")

        cve_ids = []
        for ident in adv.get("identifiers", []):
            if ident.get("type") == "CVE":
                cve_ids.append(ident["value"])
        cve_text = ", ".join(cve_ids) if cve_ids else "None"

        vulns = adv.get("vulnerabilities", [])
        affected = []
        for v in vulns[:5]:
            pkg = v.get("package", {})
            name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")
            vrange = v.get("vulnerable_version_range", "")
            if name:
                affected.append(f"- {ecosystem}/{name} {vrange}")
        affected_text = "\n".join(affected) if affected else "Not specified"

        # Truncate very long descriptions
        if len(description) > 4000:
            description = description[:4000] + "\n\n[Truncated]"

        return (
            f"## {ghsa_id}: {summary}\n\n"
            f"**Severity:** {severity}\n"
            f"**CVE(s):** {cve_text}\n"
            f"**Published:** {published}\n\n"
            f"### Description\n{description}\n\n"
            f"### Affected Packages\n{affected_text}"
        )
