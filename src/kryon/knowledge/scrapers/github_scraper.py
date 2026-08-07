"""
GitHub Scraper
==============

Scrape PoC exploits and security tools from GitHub repositories.
"""

import os
import time
from typing import Any

import requests

from .base_scraper import BaseScraper


class GitHubScraper(BaseScraper):
    """
    Scrape security-related repositories from GitHub.

    Searches for PoCs, exploits, and security tools.
    """

    def __init__(self, api_token: str | None = None):
        """
        Initialize GitHub scraper.

        Args:
            api_token: GitHub API token (optional, increases rate limit)
        """
        super().__init__()
        self.source_name = "github"
        self.api_url = "https://api.github.com"
        self.api_token = api_token or os.getenv("GITHUB_TOKEN")

    def get_source_name(self) -> str:
        """Get source name."""
        return self.source_name

    def scrape(
        self,
        keywords: list[str] | None = None,
        topics: list[str] | None = None,
        min_stars: int = 10,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Scrape GitHub for security repositories.

        Args:
            keywords: Search keywords (e.g., ["CVE", "exploit", "poc"])
            topics: GitHub topics to search (e.g., ["cybersecurity", "pentest"])
            min_stars: Minimum stars for repository
            max_results: Maximum results

        Returns:
            List of repository knowledge items
        """
        self.last_scrape_time = time.time()

        if not keywords:
            keywords = self._get_default_keywords()

        all_repos = []

        # Search by keywords
        per_keyword = max(max_results // (len(keywords) + len(topics or [])), 5)
        for keyword in keywords[:10]:
            try:
                repos = self._search_repositories(keyword, min_stars, per_keyword)
                all_repos.extend(repos)
                self.rate_limit(2)
            except Exception as e:
                self.log_error(f"Error scraping keyword '{keyword}': {str(e)}")

        # Search by topics
        if topics is None:
            topics = ["cybersecurity", "pentesting", "vulnerability", "security-tools"]
        for topic in topics[:5]:
            try:
                repos = self._search_repositories(f"topic:{topic}", min_stars, per_keyword)
                all_repos.extend(repos)
                self.rate_limit(2)
            except Exception as e:
                self.log_error(f"Error scraping topic '{topic}': {str(e)}")

        # Deduplicate
        unique_repos = self.deduplicate(all_repos)
        self.scraped_count = len(unique_repos)

        return unique_repos

    def _search_repositories(self, keyword: str, min_stars: int, max_results: int) -> list[dict[str, Any]]:
        """
        Search GitHub repositories.

        Args:
            keyword: Search keyword
            min_stars: Minimum stars
            max_results: Maximum results

        Returns:
            List of repositories
        """
        headers = {}
        if self.api_token:
            headers["Authorization"] = f"token {self.api_token}"

        # Build search query
        query = f"{keyword} stars:>={min_stars}"

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": min(max_results, 100),  # API limit per page
        }

        try:
            response = requests.get(f"{self.api_url}/search/repositories", headers=headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                repos_raw = data.get("items", [])

                repos = []
                for repo in repos_raw[:max_results]:
                    content = self._format_repository(repo)
                    metadata = self._extract_metadata(repo)

                    repos.append({"content": content, "metadata": metadata})

                return repos

            elif response.status_code == 403:
                self.log_error("GitHub API rate limit exceeded")
                return []
            else:
                self.log_error(f"GitHub API error: HTTP {response.status_code}")
                return []

        except requests.Timeout:
            self.log_error(f"Timeout searching for '{keyword}'")
            return []
        except Exception as e:
            self.log_error(f"Error: {str(e)}")
            return []

    def _format_repository(self, repo: dict) -> str:
        """Format repository as knowledge text."""
        name = repo.get("full_name", "Unknown")
        description = repo.get("description", "No description")
        stars = repo.get("stargazers_count", 0)
        url = repo.get("html_url", "")
        language = repo.get("language", "Unknown")
        topics = repo.get("topics", [])
        updated = repo.get("updated_at", "Unknown")

        # Get README if available
        readme = self._get_readme(repo.get("full_name", ""))

        topics_text = ", ".join(topics) if topics else "No topics"

        formatted = f"""**GitHub Repository: {name}**

**Description:** {description}
**Stars:** {stars}
**Language:** {language}
**Topics:** {topics_text}
**Last Updated:** {updated}
**URL:** {url}

**README Preview:**
{readme[:2000] if readme else "README not available"}
"""

        return formatted

    def _get_readme(self, repo_full_name: str) -> str:
        """
        Get README content from repository.

        Args:
            repo_full_name: Full repository name (owner/repo)

        Returns:
            README content
        """
        headers = {}
        if self.api_token:
            headers["Authorization"] = f"token {self.api_token}"

        try:
            response = requests.get(f"{self.api_url}/repos/{repo_full_name}/readme", headers=headers, timeout=10)

            if response.status_code == 200:
                import base64

                content = response.json().get("content", "")
                # Decode base64 content
                readme = base64.b64decode(content).decode("utf-8", errors="ignore")
                return readme
            else:
                return ""

        except Exception:
            return ""

    def _extract_metadata(self, repo: dict) -> dict[str, Any]:
        """Extract metadata from repository."""
        return {
            "source": self.source_name,
            "repo_name": repo.get("full_name", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language") or "",
            "topics": ", ".join(repo.get("topics", [])),
            "url": repo.get("html_url", ""),
            "type": "tool",
            "timestamp": time.time(),
        }

    def _get_default_keywords(self) -> list[str]:
        """Get default search keywords."""
        return [
            "CVE exploit",
            "PoC vulnerability",
            "pentesting tool",
            "security scanner",
            "privilege escalation",
            "web exploitation",
            "reverse shell",
            "payload generator",
        ]


# Convenience function
def scrape_github(**kwargs) -> list[dict]:
    """Scrape GitHub."""
    scraper = GitHubScraper()
    return scraper.scrape(**kwargs)
