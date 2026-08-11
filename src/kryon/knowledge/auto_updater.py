"""
KRYON Auto-Updater
===================

Automatic knowledge base updates from multiple sources.
"""

import logging
import threading
import time
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)


def _get_schedule():
    """Lazy import of schedule module (optional dependency in 'rag' extra)."""
    try:
        import schedule

        return schedule
    except ImportError:
        raise ImportError("schedule is required for auto-updater. Install with: pip install schedule") from None


class AutoUpdater:
    """
    Automatic knowledge base updater.

    Periodically scrapes and updates knowledge from configured sources.
    Uses SCRAPER_REGISTRY for source dispatch.
    """

    def __init__(self):
        """Initialize auto-updater."""
        self.running = False
        self.thread = None
        # Set by stop() to interrupt the scheduler loop's inter-poll wait so
        # shutdown is immediate instead of blocking up to a full poll interval
        # (the old time.sleep(60) made stop()'s join wait its 5s timeout every
        # time, adding ~5s to every server test teardown and to prod shutdown).
        self._stop_event = threading.Event()
        self.last_update: dict[str, float] = {}
        self.update_stats: deque[dict[str, Any]] = deque(maxlen=100)

    def start(
        self,
        schedule_type: str = "daily",
        sources: list[str] | None = None,
        time_of_day: str = "02:00",
    ):
        """
        Start automatic updates.

        Args:
            schedule_type: "hourly", "daily", or "weekly"
            sources: List of sources to update (default: all registered)
            time_of_day: Time for daily/weekly updates (HH:MM format)
        """
        if self.running:
            logger.info("Auto-updater already running")
            return

        if sources is None:
            from .scrapers import SCRAPER_REGISTRY

            sources = [k for k in SCRAPER_REGISTRY if k != "static-seed"]

        sched = _get_schedule()
        if schedule_type == "hourly":
            sched.every().hour.do(self._update_knowledge, sources=sources)
        elif schedule_type == "daily":
            sched.every().day.at(time_of_day).do(self._update_knowledge, sources=sources)
        elif schedule_type == "weekly":
            sched.every().week.at(time_of_day).do(self._update_knowledge, sources=sources)
        else:
            raise ValueError(f"Invalid schedule type: {schedule_type}")

        self.running = True
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()

        logger.info(
            "Auto-updater started (%s at %s), sources: %s",
            schedule_type,
            time_of_day if schedule_type != "hourly" else "every hour",
            ", ".join(sources),
        )

    def stop(self):
        """Stop automatic updates."""
        self.running = False
        self._stop_event.set()  # wake the scheduler loop out of its wait now
        if self.thread:
            self.thread.join(timeout=5)
        _get_schedule().clear()
        logger.info("Auto-updater stopped")

    def run_once(self, sources: list[str] | None = None) -> dict[str, Any]:
        """
        Run a single update cycle (for manual/CLI invocation).

        Args:
            sources: Sources to update. Defaults to all registered (except static-seed).

        Returns:
            Stats dictionary with results per source.
        """
        if sources is None:
            from .scrapers import SCRAPER_REGISTRY

            sources = [k for k in SCRAPER_REGISTRY if k != "static-seed"]

        return self._update_knowledge(sources)

    def _run_scheduler(self):
        """Run scheduler loop."""
        while self.running:
            _get_schedule().run_pending()
            # Interruptible wait: returns immediately when stop() sets the event.
            if self._stop_event.wait(60):
                break

    def _update_knowledge(self, sources: list[str]) -> dict[str, Any]:
        """
        Update knowledge base from sources.

        Args:
            sources: List of sources to update.

        Returns:
            Stats dictionary.
        """
        logger.info("Starting knowledge update from %d sources...", len(sources))
        start_time = time.time()

        stats: dict[str, Any] = {"timestamp": time.time(), "sources": {}, "total_added": 0}

        for source in sources:
            try:
                added = self._update_from_source(source)
                stats["sources"][source] = {"added": added, "success": True}
                stats["total_added"] += added
                self.last_update[source] = time.time()
            except Exception as e:
                stats["sources"][source] = {"added": 0, "success": False, "error": str(e)}
                logger.warning("Error updating %s: %s", source, e)

        elapsed = time.time() - start_time
        stats["elapsed_time"] = elapsed

        self.update_stats.append(stats)

        logger.info(
            "Update complete: %d items added in %.1fs",
            stats["total_added"],
            elapsed,
        )
        return stats

    def _update_from_source(self, source: str) -> int:
        """
        Update knowledge from a specific source using SCRAPER_REGISTRY.

        Args:
            source: Source name (must be a key in SCRAPER_REGISTRY).

        Returns:
            Number of items added.
        """
        from .rag_engine import get_rag_engine
        from .scrapers import SCRAPER_REGISTRY

        if source not in SCRAPER_REGISTRY:
            logger.warning("Unknown source: %s (available: %s)", source, list(SCRAPER_REGISTRY.keys()))
            return 0

        rag = get_rag_engine()
        scraper_cls = SCRAPER_REGISTRY[source]
        scraper = scraper_cls()
        items = scraper.scrape(max_results=50)

        added = 0
        for item in items:
            try:
                rag.add_knowledge(content=item["content"], source=source, metadata=item.get("metadata", {}))
                added += 1
            except Exception as e:
                logger.debug("Error adding item from %s: %s", source, e)

        return added

    def get_stats(self) -> dict[str, Any]:
        """Get update statistics."""
        return {
            "running": self.running,
            "last_update": self.last_update,
            "total_updates": len(self.update_stats),
            "recent_stats": list(self.update_stats)[-10:] if self.update_stats else [],
        }


# Global instance
_auto_updater = None
_auto_updater_lock = threading.Lock()


def get_auto_updater() -> AutoUpdater:
    """Get global auto-updater instance."""
    global _auto_updater
    if _auto_updater is None:
        with _auto_updater_lock:
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
