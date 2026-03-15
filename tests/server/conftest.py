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
