"""Shared dependency singletons for API routes (thread-safe, lazy-initialized)."""

from __future__ import annotations

import threading

# --- MemoryStore ---
_store = None
_store_lock = threading.Lock()


def get_store():
    """Get the singleton MemoryStore instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                from kryon.memory.store import MemoryStore

                _store = MemoryStore()
    return _store


# --- ScanScheduler ---
_scheduler = None
_scheduler_lock = threading.Lock()


def get_scheduler():
    """Get the singleton ScanScheduler instance."""
    global _scheduler
    if _scheduler is None:
        with _scheduler_lock:
            if _scheduler is None:
                from kryon.server.scheduler import ScanScheduler

                _scheduler = ScanScheduler()
    return _scheduler


# --- EngagementManager ---
_engagement_manager = None
_engagement_manager_lock = threading.Lock()


def get_engagement_manager():
    """Get the singleton EngagementManager instance."""
    global _engagement_manager
    if _engagement_manager is None:
        with _engagement_manager_lock:
            if _engagement_manager is None:
                from kryon.engagements.manager import EngagementManager

                _engagement_manager = EngagementManager()
    return _engagement_manager
