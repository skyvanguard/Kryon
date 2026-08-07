"""Seed the KRYON knowledge base with data from available scrapers.

Runs Intelligence (MITRE ATT&CK + CISA KEV), NVD, and GitHub scrapers
and inserts all results into the RAG vector database.

Usage:
    python scripts/seed_knowledge.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure src is importable
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def seed() -> dict[str, int]:
    """Run scrapers and insert results into the knowledge base.

    Returns:
        Dict mapping source name to number of documents inserted.
    """
    from kryon.knowledge.rag_engine import get_rag_engine

    engine = get_rag_engine()
    totals: dict[str, int] = {}

    # --- Intelligence scraper (MITRE ATT&CK + CISA KEV) ---
    try:
        from kryon.knowledge.scrapers.intelligence_scraper import IntelligenceScraper

        logger.info("Running Intelligence scraper (MITRE + CISA KEV)...")
        scraper = IntelligenceScraper(max_items=200)
        items = scraper.scrape()
        for item in items:
            engine.add_knowledge(
                content=item["content"],
                source=item["metadata"].get("source", "intelligence-feed"),
                metadata=item["metadata"],
            )
        totals["intelligence"] = len(items)
        logger.info("Intelligence scraper: %d items", len(items))
    except Exception as e:
        logger.warning("Intelligence scraper failed: %s", e)
        totals["intelligence"] = 0

    # --- NVD scraper (recent CVEs) ---
    try:
        from kryon.knowledge.scrapers.nvd_scraper import NVDScraper

        logger.info("Running NVD scraper (last 30 days, max 200)...")
        scraper = NVDScraper()
        items = scraper.scrape(days_back=30, max_results=200)
        for item in items:
            engine.add_knowledge(
                content=item["content"],
                source=item["metadata"].get("source", "nvd"),
                metadata=item["metadata"],
            )
        totals["nvd"] = len(items)
        logger.info("NVD scraper: %d items", len(items))
    except Exception as e:
        logger.warning("NVD scraper failed: %s", e)
        totals["nvd"] = 0

    # --- GitHub scraper (security tools & PoCs) ---
    try:
        from kryon.knowledge.scrapers.github_scraper import GitHubScraper

        logger.info("Running GitHub scraper (security tools, min 50 stars, max 50)...")
        scraper = GitHubScraper()
        items = scraper.scrape(min_stars=50, max_results=50)
        for item in items:
            engine.add_knowledge(
                content=item["content"],
                source=item["metadata"].get("source", "github"),
                metadata=item["metadata"],
            )
        totals["github"] = len(items)
        logger.info("GitHub scraper: %d items", len(items))
    except Exception as e:
        logger.warning("GitHub scraper failed: %s", e)
        totals["github"] = 0

    total = sum(totals.values())
    logger.info("Seed complete. Total documents: %d | Breakdown: %s", total, totals)
    return totals


if __name__ == "__main__":
    seed()
