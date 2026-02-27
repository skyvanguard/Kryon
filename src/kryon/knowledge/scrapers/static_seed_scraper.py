"""
Static Seed Scraper
===================

Load static seed data from JSON files for initial knowledge base population.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any

from .base_scraper import BaseScraper

logger = logging.getLogger(__name__)

# Default seed data directory (relative to this file)
_SEED_DATA_DIR = Path(__file__).resolve().parent.parent / "seed_data"


class StaticSeedScraper(BaseScraper):
    """
    Load static seed data from JSON files.

    Reads all .json files from the seed_data/ directory and returns
    them as knowledge items for RAG indexing.
    """

    def __init__(self, seed_dir: str | Path | None = None):
        """
        Initialize static seed scraper.

        Args:
            seed_dir: Path to seed data directory. Defaults to built-in seed_data/.
        """
        super().__init__()
        self.seed_dir = Path(seed_dir) if seed_dir else _SEED_DATA_DIR

    def get_source_name(self) -> str:
        return "static-seed"

    def scrape(self, **kwargs) -> list[dict[str, Any]]:
        """
        Load all seed data from JSON files.

        Returns:
            List of knowledge items with content and metadata.
        """
        self.last_scrape_time = time.time()

        if not self.seed_dir.is_dir():
            self.log_error(f"Seed data directory not found: {self.seed_dir}")
            return []

        items: list[dict[str, Any]] = []

        for json_file in sorted(self.seed_dir.glob("*.json")):
            try:
                loaded = self._load_json_file(json_file)
                items.extend(loaded)
                logger.info("Loaded %d items from %s", len(loaded), json_file.name)
            except Exception as e:
                self.log_error(f"Error loading {json_file.name}: {e}")

        items = self.deduplicate(items)
        self.scraped_count = len(items)
        return items

    def _load_json_file(self, path: Path) -> list[dict[str, Any]]:
        """Load and validate a single JSON seed file."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError(f"Expected JSON array in {path.name}, got {type(data).__name__}")

        items: list[dict[str, Any]] = []
        for entry in data:
            content = entry.get("content")
            if not content or not isinstance(content, str):
                continue

            metadata = entry.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            # Ensure source is set
            if "source" not in metadata:
                metadata["source"] = self.get_source_name()

            items.append({"content": content, "metadata": metadata})

        return items
