"""
CTF Writeup Scraper
===================

Scrape CTF writeups from various sources (HTB, THM, blogs).
"""

import time
from typing import Any, Optional

import requests

from .base_scraper import BaseScraper


class WriteupScraper(BaseScraper):
    """
    Scrape CTF writeups from multiple sources.

    Sources:
    - HackTheBox writeups (from various blogs)
    - TryHackMe writeups
    - CTFtime writeups
    - Security blogs
    """

    def __init__(self):
        """Initialize writeup scraper."""
        super().__init__()
        self.source_name = "writeups"

    def get_source_name(self) -> str:
        """Get source name."""
        return self.source_name

    def scrape(self, sources: Optional[list[str]] = None, max_results: int = 100) -> list[dict[str, Any]]:
        """
        Scrape writeups from various sources.

        Args:
            sources: List of sources to scrape (default: all)
            max_results: Maximum results

        Returns:
            List of writeup knowledge items
        """
        self.last_scrape_time = time.time()

        if not sources:
            sources = ["github_writeups", "ctf_collections", "medium_writeups"]

        all_writeups = []

        for source in sources:
            try:
                if source == "github_writeups":
                    writeups = self._scrape_github_writeups(max_results // len(sources))
                elif source == "ctf_collections":
                    writeups = self._scrape_ctf_collections(max_results // len(sources))
                elif source == "medium_writeups":
                    writeups = self._scrape_medium_writeups(max_results // len(sources))
                else:
                    continue

                all_writeups.extend(writeups)
                self.rate_limit(2)

            except Exception as e:
                self.log_error(f"Error scraping source '{source}': {str(e)}")

        # Deduplicate
        unique_writeups = self.deduplicate(all_writeups)
        self.scraped_count = len(unique_writeups)

        return unique_writeups

    def _scrape_github_writeups(self, max_results: int) -> list[dict[str, Any]]:
        """
        Scrape writeups from GitHub.

        Searches for repositories tagged with 'writeup', 'ctf', 'hackthebox', 'tryhackme'.
        """
        writeups = []

        search_queries = [
            "HackTheBox writeup",
            "TryHackMe writeup",
            "CTF writeup",
            "bug bounty writeup",
            "pentest writeup",
        ]

        for query in search_queries[:2]:  # Limit to avoid rate limit
            try:
                params = {
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": max_results // len(search_queries),
                }

                response = requests.get("https://api.github.com/search/repositories", params=params, timeout=30)

                if response.status_code == 200:
                    data = response.json()
                    repos = data.get("items", [])

                    for repo in repos[: max_results // len(search_queries)]:
                        content = self._format_github_writeup(repo)
                        metadata = {
                            "source": self.source_name,
                            "subsource": "github",
                            "repo_name": repo.get("full_name", ""),
                            "url": repo.get("html_url", ""),
                            "type": "writeup",
                            "timestamp": time.time(),
                        }

                        writeups.append({"content": content, "metadata": metadata})

                self.rate_limit(2)

            except Exception as e:
                self.log_error(f"GitHub writeup error: {str(e)}")

        return writeups

    def _format_github_writeup(self, repo: dict) -> str:
        """Format GitHub writeup repository."""
        name = repo.get("full_name", "Unknown")
        description = repo.get("description", "No description")
        url = repo.get("html_url", "")
        updated = repo.get("updated_at", "Unknown")

        formatted = f"""**CTF Writeup Repository: {name}**

**Description:** {description}
**Last Updated:** {updated}
**URL:** {url}

**Type:** CTF Writeup Collection
**Platform:** GitHub

**Use Case:** Learn attack techniques and methodologies from documented CTF solutions.
"""

        return formatted

    def _scrape_ctf_collections(self, max_results: int) -> list[dict[str, Any]]:
        """
        Scrape curated CTF writeup collections from GitHub.

        Targets well-known aggregation repositories.
        """
        curated_repos = [
            "CTFd/ctfd",
            "apsdehal/awesome-ctf",
            "zardus/ctf-tools",
            "w181496/Web-CTF-Cheatsheet",
            "JohnHammond/ctf-katana",
        ]

        writeups = []
        for repo_name in curated_repos[:max_results]:
            try:
                response = requests.get(
                    f"https://api.github.com/repos/{repo_name}",
                    timeout=15,
                )
                if response.status_code == 200:
                    repo = response.json()
                    content = self._format_github_writeup(repo)
                    writeups.append(
                        {
                            "content": content,
                            "metadata": {
                                "source": self.source_name,
                                "subsource": "ctf-collection",
                                "repo_name": repo.get("full_name", ""),
                                "url": repo.get("html_url", ""),
                                "type": "writeup",
                                "timestamp": time.time(),
                            },
                        }
                    )
                self.rate_limit(1.5)
            except Exception as e:
                self.log_error(f"CTF collection error for {repo_name}: {e}")

        return writeups

    def _scrape_medium_writeups(self, max_results: int) -> list[dict[str, Any]]:
        """
        Scrape writeups from Medium.

        Note: Medium doesn't have a public API, so this is a simplified version.
        In production, you'd use web scraping with BeautifulSoup.
        """
        # Placeholder - in production this would scrape Medium
        # For now, return example structure
        writeups = []

        # Example knowledge about common writeup patterns
        example_writeup = {
            "content": """**CTF Writeup Methodology**

**Common CTF Attack Patterns:**

1. **Reconnaissance:**
   - nmap for port scanning
   - gobuster/dirbuster for directory enumeration
   - whatweb for technology fingerprinting

2. **Initial Access:**
   - Default credentials
   - SQL injection
   - File upload vulnerabilities
   - Command injection
   - XXE, SSRF, LFI

3. **Privilege Escalation (Linux):**
   - SUID binaries
   - Sudo misconfigurations
   - Kernel exploits
   - Cron jobs

4. **Privilege Escalation (Windows):**
   - AlwaysInstallElevated
   - Unquoted service paths
   - DLL hijacking
   - Token impersonation

**Tools Commonly Used:**
- LinPEAS / WinPEAS (privilege escalation)
- Burp Suite (web testing)
- Metasploit (exploitation)
- nc / socat (reverse shells)
""",
            "metadata": {
                "source": self.source_name,
                "subsource": "methodology",
                "type": "writeup",
                "timestamp": time.time(),
            },
        }

        writeups.append(example_writeup)

        return writeups


# Convenience function
def scrape_writeups(**kwargs) -> list[dict]:
    """Scrape CTF writeups."""
    scraper = WriteupScraper()
    return scraper.scrape(**kwargs)
