"""
Base Scraper Class
==================

Abstract base class for all knowledge scrapers.
"""

import hashlib
import time
from abc import ABC, abstractmethod
from typing import Any


class BaseScraper(ABC):
    """
    Abstract base class for knowledge scrapers.

    All scrapers must implement:
    - scrape(): Main scraping method
    - get_source_name(): Source identifier
    """

    def __init__(self):
        """Initialize base scraper."""
        self.scraped_count = 0
        self.errors = []
        self.last_scrape_time = None

    @abstractmethod
    def scrape(self, **kwargs) -> list[dict[str, Any]]:
        """
        Scrape knowledge from source.

        Returns:
            List of knowledge items, each with:
            - content: Main text content
            - metadata: Dictionary with source-specific metadata
        """
        pass

    @abstractmethod
    def get_source_name(self) -> str:
        """
        Get source identifier.

        Returns:
            Source name (e.g., "exploit-db", "nvd")
        """
        pass

    def generate_id(self, content: str) -> str:
        """
        Generate unique ID for content.

        Args:
            content: Content text

        Returns:
            MD5 hash of content
        """
        return hashlib.md5(content.encode()).hexdigest()  # nosemgrep: insecure-hash-algorithm-md5

    def deduplicate(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Remove duplicate items based on content.

        Args:
            items: List of knowledge items

        Returns:
            Deduplicated list
        """
        seen_ids = set()
        unique_items = []

        for item in items:
            content = item.get("content", "")
            item_id = self.generate_id(content)

            if item_id not in seen_ids:
                seen_ids.add(item_id)
                unique_items.append(item)

        return unique_items

    def rate_limit(self, delay: float = 1.0):
        """
        Apply rate limiting between requests.

        Args:
            delay: Delay in seconds
        """
        time.sleep(delay)

    def log_error(self, error: str):
        """
        Log scraping error.

        Args:
            error: Error message
        """
        self.errors.append({"timestamp": time.time(), "error": error})

    def get_stats(self) -> dict[str, Any]:
        """
        Get scraping statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "source": self.get_source_name(),
            "scraped_count": self.scraped_count,
            "errors_count": len(self.errors),
            "last_scrape": self.last_scrape_time,
        }
