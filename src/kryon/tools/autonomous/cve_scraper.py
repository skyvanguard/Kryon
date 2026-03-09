"""
KRYON CVE Scraper - Auto-Discovery of New Exploits
===================================================

Automatic discovery and integration of new CVEs and exploits.

Clearance Level: Omega-Strategic
Mission: Stay updated with latest vulnerabilities automatically
"""

import json
import time
from datetime import datetime, timedelta
from typing import Any, Optional


class CVEScraper:
    """Automatic CVE discovery and exploit database updater."""

    def __init__(self):
        """Initialize CVE scraper."""
        self.discovered_cves = []

    def scrape_new_cves(
        self,
        services: Optional[list[str]] = None,
        days_back: int = 30,
        severity_min: str = "medium",
    ) -> list[dict[str, Any]]:
        """
        Scrape new CVEs from public sources.

        Args:
            services: Filter by services (e.g., ["apache", "nginx"])
            days_back: How many days back to search
            severity_min: Minimum severity (low/medium/high/critical)

        Returns:
            List of discovered CVEs
        """
        discovered = []

        # Source 1: NVD API (National Vulnerability Database)
        nvd_cves = self._scrape_nvd(services, days_back, severity_min)
        discovered.extend(nvd_cves)

        # Source 2: Exploit-DB search
        exploitdb_results = self._scrape_exploitdb(services)
        discovered.extend(exploitdb_results)

        # Source 3: GitHub PoC search
        github_pocs = self._scrape_github_pocs(services, days_back)
        discovered.extend(github_pocs)

        # Deduplicate
        seen = set()
        unique_cves = []
        for cve in discovered:
            cve_id = cve.get("cve_id")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                unique_cves.append(cve)

        self.discovered_cves = unique_cves
        return unique_cves

    def _scrape_nvd(self, services: Optional[list[str]], days_back: int, severity_min: str) -> list[dict]:
        """Scrape NVD (National Vulnerability Database)."""
        try:
            import requests

            # NVD API endpoint
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)

            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            }

            response = requests.get(base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                cves = []
                for vuln in vulnerabilities[:50]:  # Limit to first 50
                    cve_item = vuln.get("cve", {})
                    cve_id = cve_item.get("id")

                    # Get description
                    descriptions = cve_item.get("descriptions", [])
                    desc = descriptions[0].get("value", "") if descriptions else ""

                    # Filter by service
                    if services:
                        if not any(svc.lower() in desc.lower() for svc in services):
                            continue

                    # Get severity
                    metrics = cve_item.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0]
                    severity = cvss_v3.get("cvssData", {}).get("baseSeverity", "UNKNOWN")

                    cves.append(
                        {
                            "cve_id": cve_id,
                            "description": desc[:200],  # Truncate
                            "severity": severity,
                            "source": "NVD",
                            "published": cve_item.get("published"),
                            "poc_available": False,  # Will be updated later
                        }
                    )

                return cves

        except Exception as e:
            print(f"NVD scraping error: {e}")
            return []

        return []

    def _scrape_exploitdb(self, services: Optional[list[str]]) -> list[dict]:
        """Scrape Exploit-DB for recent exploits."""
        # Exploit-DB doesn't have a public API, but we can search local database
        import subprocess

        try:
            # Search exploitdb using searchsploit
            results = []

            if services:
                for service in services:
                    cmd = ["searchsploit", "-j", service]
                    output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                    if output.returncode == 0:
                        try:
                            data = json.loads(output.stdout)
                            exploits = data.get("RESULTS_EXPLOIT", [])

                            for exploit in exploits[:10]:  # First 10 per service
                                results.append(
                                    {
                                        "cve_id": exploit.get("Codes", ["N/A"])[0] if exploit.get("Codes") else "N/A",
                                        "description": exploit.get("Title", ""),
                                        "severity": "UNKNOWN",
                                        "source": "Exploit-DB",
                                        "poc_available": True,
                                        "exploit_path": exploit.get("Path", ""),
                                    }
                                )

                        except json.JSONDecodeError:
                            pass

            return results

        except Exception as e:
            print(f"Exploit-DB scraping error: {e}")
            return []

    def _scrape_github_pocs(self, services: Optional[list[str]], days_back: int) -> list[dict]:
        """Search GitHub for PoC exploits."""
        try:
            import requests

            results = []
            headers = {}

            # GitHub API token (if available)
            import os

            github_token = os.getenv("GITHUB_TOKEN")
            if github_token:
                headers["Authorization"] = f"token {github_token}"

            if services:
                for service in services:
                    # Search for CVE PoCs
                    search_query = f"CVE {service} PoC"
                    url = f"https://api.github.com/search/repositories?q={search_query}&sort=updated&order=desc"

                    response = requests.get(url, headers=headers, timeout=15)

                    if response.status_code == 200:
                        data = response.json()
                        repos = data.get("items", [])[:5]  # Top 5

                        for repo in repos:
                            results.append(
                                {
                                    "cve_id": "GITHUB_POC",
                                    "description": repo.get("description", repo.get("name", ""))[:200],
                                    "severity": "UNKNOWN",
                                    "source": "GitHub",
                                    "poc_available": True,
                                    "repo_url": repo.get("html_url"),
                                    "stars": repo.get("stargazers_count", 0),
                                }
                            )

                    # Rate limiting
                    time.sleep(1)

            return results

        except Exception as e:
            print(f"GitHub scraping error: {e}")
            return []

    def integrate_cve_to_database(self, cve: dict[str, Any]) -> bool:
        """
        Integrate discovered CVE into exploit database.

        Args:
            cve: CVE information

        Returns:
            True if integrated successfully
        """
        from .decision_engine import EXPLOIT_DATABASE

        # Parse CVE to determine service
        desc = cve.get("description", "").lower()

        # Map to service
        service = None
        service_keywords = {
            "apache": "apache",
            "nginx": "http",
            "ssh": "ssh",
            "mysql": "mysql",
            "postgresql": "postgresql",
            "smb": "smb",
            "ftp": "ftp",
            "rdp": "rdp",
        }

        for keyword, svc in service_keywords.items():
            if keyword in desc:
                service = svc
                break

        if not service:
            return False

        # Create exploit entry
        exploit = {
            "name": f"auto_discovered_{cve.get('cve_id', 'unknown')}",
            "type": "discovered",
            "cve": cve.get("cve_id"),
            "description": cve.get("description", ""),
            "difficulty": "medium",
            "success_probability": 0.3,  # Unknown, conservative estimate
            "source": cve.get("source", "unknown"),
            "requires_auth": False,
            "discovered_at": time.time(),
        }

        # Add to database
        if service in EXPLOIT_DATABASE:
            # Check if not already exists
            existing = [e for e in EXPLOIT_DATABASE[service] if e.get("cve") == cve.get("cve_id")]

            if not existing:
                EXPLOIT_DATABASE[service].append(exploit)
                return True

        return False

    def auto_update_exploits(self, services: list[str], schedule: str = "daily") -> dict[str, Any]:
        """
        Automatically update exploit database on schedule.

        Args:
            services: Services to monitor
            schedule: Update frequency (hourly/daily/weekly)

        Returns:
            Update statistics
        """
        # Scrape new CVEs
        new_cves = self.scrape_new_cves(services=services, days_back=7)

        stats = {"scraped": len(new_cves), "integrated": 0, "failed": 0}

        # Integrate each CVE
        for cve in new_cves:
            if self.integrate_cve_to_database(cve):
                stats["integrated"] += 1
            else:
                stats["failed"] += 1

        return stats


# Global instance
_cve_scraper = None
_cve_scraper_lock = __import__("threading").Lock()


def get_cve_scraper() -> CVEScraper:
    """Get global CVE scraper instance."""
    global _cve_scraper
    if _cve_scraper is None:
        with _cve_scraper_lock:
            if _cve_scraper is None:
                _cve_scraper = CVEScraper()
    return _cve_scraper


# Convenience function
def auto_update_exploits(services: list[str]) -> dict:
    """Auto-update exploit database."""
    return get_cve_scraper().auto_update_exploits(services)
