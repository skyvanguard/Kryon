"""
KRYON Auto-Updater
===================

Automatic knowledge base updates from multiple sources.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

import threading
import time
from typing import Any, Optional

import schedule


class AutoUpdater:
    """
    Automatic knowledge base updater.

    Periodically scrapes and updates knowledge from configured sources.
    """

    def __init__(self):
        """Initialize auto-updater."""
        self.running = False
        self.thread = None
        self.last_update = {}
        self.update_stats = []

    def start(
        self,
        schedule_type: str = "daily",
        sources: Optional[list[str]] = None,
        time_of_day: str = "02:00",
    ):
        """
        Start automatic updates.

        Args:
            schedule_type: "hourly", "daily", or "weekly"
            sources: List of sources to update (default: all)
            time_of_day: Time for daily/weekly updates (HH:MM format)
        """
        if self.running:
            print("Auto-updater already running")
            return

        if sources is None:
            sources = ["exploit-db", "nvd", "github", "writeups"]

        # Schedule updates
        if schedule_type == "hourly":
            schedule.every().hour.do(self._update_knowledge, sources=sources)
        elif schedule_type == "daily":
            schedule.every().day.at(time_of_day).do(self._update_knowledge, sources=sources)
        elif schedule_type == "weekly":
            schedule.every().week.at(time_of_day).do(self._update_knowledge, sources=sources)
        else:
            raise ValueError(f"Invalid schedule type: {schedule_type}")

        # Start scheduler thread
        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()

        print(
            f"✅ Auto-updater started ({schedule_type} at {time_of_day if schedule_type != 'hourly' else 'every hour'})"
        )
        print(f"📚 Sources: {', '.join(sources)}")

    def stop(self):
        """Stop automatic updates."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        schedule.clear()
        print("⏹️  Auto-updater stopped")

    def _run_scheduler(self):
        """Run scheduler loop."""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

    def _update_knowledge(self, sources: list[str]):
        """
        Update knowledge base from sources.

        Args:
            sources: List of sources to update
        """
        print(f"\n🔄 Starting knowledge update from {len(sources)} sources...")
        start_time = time.time()

        stats = {"timestamp": time.time(), "sources": {}, "total_added": 0}

        for source in sources:
            try:
                added = self._update_from_source(source)
                stats["sources"][source] = {"added": added, "success": True}
                stats["total_added"] += added
                self.last_update[source] = time.time()

            except Exception as e:
                stats["sources"][source] = {"added": 0, "success": False, "error": str(e)}
                print(f"❌ Error updating {source}: {e}")

        elapsed = time.time() - start_time
        stats["elapsed_time"] = elapsed

        self.update_stats.append(stats)

        print("\n✅ Update complete!")
        print(f"📊 Added {stats['total_added']} new knowledge items")
        print(f"⏱️  Time: {elapsed:.1f}s")

    def _update_from_source(self, source: str) -> int:
        """
        Update knowledge from specific source.

        Args:
            source: Source name

        Returns:
            Number of items added
        """
        from .rag_engine import get_rag_engine
        from .scrapers import ExploitDBScraper, GitHubScraper, NVDScraper, WriteupScraper

        rag = get_rag_engine()

        if source == "exploit-db":
            scraper = ExploitDBScraper()
            items = scraper.scrape(max_results=50)
        elif source == "nvd":
            scraper = NVDScraper()
            items = scraper.scrape(days_back=7, max_results=50)
        elif source == "github":
            scraper = GitHubScraper()
            items = scraper.scrape(max_results=20)
        elif source == "writeups":
            scraper = WriteupScraper()
            items = scraper.scrape(max_results=20)
        else:
            print(f"Unknown source: {source}")
            return 0

        # Add to knowledge base
        added = 0
        for item in items:
            try:
                rag.add_knowledge(content=item["content"], source=source, metadata=item.get("metadata", {}))
                added += 1
            except Exception as e:
                print(f"Error adding item from {source}: {e}")

        return added

    def get_stats(self) -> dict[str, Any]:
        """Get update statistics."""
        return {
            "running": self.running,
            "last_update": self.last_update,
            "total_updates": len(self.update_stats),
            "recent_stats": self.update_stats[-10:] if self.update_stats else [],
        }


# Global instance
_auto_updater = None


def get_auto_updater() -> AutoUpdater:
    """Get global auto-updater instance."""
    global _auto_updater
    if _auto_updater is None:
        _auto_updater = AutoUpdater()
    return _auto_updater


# Convenience functions
def start_auto_updater(**kwargs):
    """Start automatic knowledge updates."""
    return get_auto_updater().start(**kwargs)


def stop_auto_updater():
    """Stop automatic knowledge updates."""
    return get_auto_updater().stop()


def auto_update_knowledge(sources: list[str]):
    """
    Manually trigger knowledge update.

    Args:
        sources: List of sources to update
    """
    updater = get_auto_updater()
    updater._update_knowledge(sources)
