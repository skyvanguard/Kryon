"""Fixtures for server tests."""

import os

import pytest

from kryon.server import ServerConfig, create_app


@pytest.fixture(autouse=True)
def _reset_deps_store():
    """Reset the deps singleton store before each test to avoid cross-thread SQLite errors."""
    import kryon.server.deps as deps_mod

    old = deps_mod._store
    deps_mod._store = None
    yield
    deps_mod._store = old


@pytest.fixture(autouse=True)
def _allow_unauthenticated(monkeypatch):
    """Allow unauthenticated access in tests (simulates dev mode)."""
    monkeypatch.setenv("KRYON_ALLOW_UNAUTHENTICATED", "true")


@pytest.fixture(autouse=True)
def _auto_isolate_vector_db(isolate_vector_db):
    """Isolate the knowledge vector store for every server test (see root
    conftest ``isolate_vector_db``)."""
    yield


@pytest.fixture(autouse=True)
def _skip_kb_seed(monkeypatch):
    """Neutralize the knowledge-base work the app lifespan does on startup.

    On a fresh/isolated vector store the lifespan (a) calls get_knowledge_stats()
    — which spins up ChromaDB (~0.2-0.6s per test) — and (b) seeds ~500 items via
    real embeddings, loading (and maybe downloading) a sentence-transformers model
    that HANGS `with TestClient(app)` in wait_startup. Server tests don't exercise
    the KB, so stub both: report a non-empty store (skips seeding + the ChromaDB
    init) and no-op the seed as a belt-and-suspenders. App code imports these names
    from ``kryon.knowledge`` at lifespan time, so patch them there. Tests that DO
    hit /knowledge/* still init ChromaDB lazily on the first request."""
    import kryon.knowledge as knowledge

    monkeypatch.setattr(
        knowledge, "get_knowledge_stats", lambda *a, **k: {"total_knowledge_items": 1}, raising=False
    )
    monkeypatch.setattr(knowledge, "seed_knowledge_base", lambda *a, **k: {"added": 0}, raising=False)


@pytest.fixture
def server_config():
    return ServerConfig(api_keys=[])


@pytest.fixture
def app(server_config):
    return create_app(server_config)


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient

    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_app():
    config = ServerConfig(api_keys=["test-key-123"])
    return create_app(config)


@pytest.fixture
def auth_client(auth_app):
    from starlette.testclient import TestClient

    with TestClient(auth_app) as c:
        yield c
