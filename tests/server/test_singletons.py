"""Tests for thread-safe singleton patterns in route modules."""

import threading

import pytest


def test_clients_store_singleton():
    """Multiple calls to _get_store() return the same object."""
    from kryon.server.routes import clients

    # Reset to test fresh initialization
    clients._store = None
    results = []

    def _init():
        results.append(id(clients._get_store()))

    threads = [threading.Thread(target=_init) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All threads should get the same instance
    assert len(set(results)) == 1
    clients._store = None  # cleanup


def test_engagements_manager_singleton():
    """Multiple calls to _get_manager() return the same object."""
    from kryon.server.routes import engagements

    engagements._manager = None
    results = []

    def _init():
        results.append(id(engagements._get_manager()))

    threads = [threading.Thread(target=_init) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(results)) == 1
    engagements._manager = None
