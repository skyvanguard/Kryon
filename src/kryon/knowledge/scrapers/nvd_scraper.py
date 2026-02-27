"""
NVD Scraper
===========

Scrape vulnerability information from NIST National Vulnerability Database.
"""

import time
from datetime import datetime, timedelta
from typing import Any, Optional

import requests

from .base_scraper import BaseScraper


class NVDScraper(BaseScraper):
    """
    Scrape vulnerabilities from NVD API.

    Uses official NVD REST API 2.0.
    """

    def __init__(self):
        """Initialize NVD scraper."""
        super().__init__()
        self.source_name = "nvd"
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def get_source_name(self) -> str:
        """Get source name."""
        return self.source_name

    def scrape(
        self,
        days_back: int = 30,
        keywords: Optional[list[str]] = None,
        severity_min: str = "MEDIUM",
        max_results: int = 500,
        cvss_min: float = 0.0,
    ) -> list[dict[str, Any]]:
        """
        Scrape CVEs from NVD.

        Args:
            days_back: How many days back to search
            keywords: Optional keyword filter
            severity_min: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
            max_results: Maximum results
            cvss_min: Minimum CVSS score (0.0-10.0)

        Returns:
            List of CVE knowledge items
        """
        self.last_scrape_time = time.time()

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(max_results, 2000),  # API limit
        }

        try:
            response = requests.get(self.api_url, params=params, timeout=60)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                cves = []
                for vuln in vulnerabilities[:max_results]:
                    cve_item = vuln.get("cve", {})

                    # Filter by keywords if provided
                    if keywords:
                        desc = self._get_description(cve_item)
                        if not any(kw.lower() in desc.lower() for kw in keywords):
                            continue

                    # Filter by severity
                    severity = self._get_severity(cve_item)
                    if not self._meets_severity_threshold(severity, severity_min):
                        continue

                    # Filter by CVSS score
                    score = self._get_cvss_score(cve_item)
                    if cvss_min > 0 and score < cvss_min:
                        continue

                    content = self._format_cve(cve_item)
                    metadata = self._extract_metadata(cve_item)

                    cves.append({"content": content, "metadata": metadata})

                self.scraped_count = len(cves)
                return cves

            else:
                self.log_error(f"NVD API error: HTTP {response.status_code}")
                return []

        except requests.Timeout:
            self.log_error("NVD API timeout")
            return []
        except Exception as e:
            self.log_error(f"NVD scraping error: {str(e)}")
            return []

    def _get_description(self, cve_item: dict) -> str:
        """Extract description from CVE."""
        descriptions = cve_item.get("descriptions", [])
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    def _get_severity(self, cve_item: dict) -> str:
        """Extract severity from CVE."""
        metrics = cve_item.get("metrics", {})

        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            return cvss_v31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")

        # Try CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            return cvss_v30[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")

        return "UNKNOWN"

    def _get_cvss_score(self, cve_item: dict) -> float:
        """Extract CVSS score from CVE."""
        metrics = cve_item.get("metrics", {})

        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            return cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)

        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            return cvss_v30[0].get("cvssData", {}).get("baseScore", 0.0)

        return 0.0

    def _meets_severity_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets threshold."""
        severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        sev_level = severity_levels.get(severity, 0)
        threshold_level = severity_levels.get(threshold, 0)

        return sev_level >= threshold_level

    def _format_cve(self, cve_item: dict) -> str:
        """Format CVE as structured markdown knowledge text."""
        cve_id = cve_item.get("id", "Unknown")
        description = self._get_description(cve_item)
        severity = self._get_severity(cve_item)
        cvss_score = self._get_cvss_score(cve_item)
        published = cve_item.get("published", "Unknown")

        # Get references with tags
        references = cve_item.get("references", [])
        ref_lines = []
        for ref in references[:8]:
            url = ref.get("url", "")
            tags = ", ".join(ref.get("tags", []))
            tag_suffix = f" ({tags})" if tags else ""
            ref_lines.append(f"- {url}{tag_suffix}")
        ref_text = "\n".join(ref_lines)

        # Get weaknesses (CWE)
        weaknesses = cve_item.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)
        cwe_text = ", ".join(cwe_ids) if cwe_ids else "Not specified"

        # Get CVSS vector string
        vector = self._get_cvss_vector(cve_item)
        vector_text = f"\n**CVSS Vector:** {vector}" if vector else ""

        formatted = f"""## {cve_id}

**Severity:** {severity} (CVSS: {cvss_score}){vector_text}
**Published:** {published}
**Weakness:** {cwe_text}

### Description
{description}

### References
{ref_text if ref_text else "No references available"}
"""

        return formatted

    def _get_cvss_vector(self, cve_item: dict) -> str:
        """Extract CVSS vector string."""
        metrics = cve_item.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                return entries[0].get("cvssData", {}).get("vectorString", "")
        return ""

    def _extract_metadata(self, cve_item: dict) -> dict[str, Any]:
        """Extract metadata from CVE."""
        return {
            "source": self.source_name,
            "cve_id": cve_item.get("id", ""),
            "severity": self._get_severity(cve_item),
            "cvss_score": self._get_cvss_score(cve_item),
            "published": cve_item.get("published", ""),
            "type": "vulnerability",
            "timestamp": time.time(),
        }


# Convenience function
def scrape_nvd(**kwargs) -> list[dict]:
    """Scrape NVD."""
    scraper = NVDScraper()
    return scraper.scrape(**kwargs)
