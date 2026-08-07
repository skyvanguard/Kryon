"""Tests for thread-safe singleton patterns in deps module."""

import threading

import pytest


def test_store_singleton():
    """Multiple calls to get_store() return the same object."""
    import kryon.server.deps as deps

    # Reset to test fresh initialization
    deps._store = None
    results = []

    def _init():
        results.append(id(deps.get_store()))

    threads = [threading.Thread(target=_init) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All threads should get the same instance
    assert len(set(results)) == 1
    deps._store = None  # cleanup


def test_engagement_manager_singleton():
    """Multiple calls to get_engagement_manager() return the same object."""
    import kryon.server.deps as deps

    deps._engagement_manager = None
    results = []

    def _init():
        results.append(id(deps.get_engagement_manager()))

    threads = [threading.Thread(target=_init) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(results)) == 1
    deps._engagement_manager = None
