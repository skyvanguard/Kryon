"""Tests for structured logging and request ID middleware."""

import logging

import pytest


@pytest.fixture
def debug_app():
    from kryon.server import ServerConfig, create_app

    return create_app(ServerConfig(api_keys=[], debug=True))


@pytest.fixture
def debug_client(debug_app):
    from starlette.testclient import TestClient

    with TestClient(debug_app) as c:
        yield c


def test_request_id_generated(client):
    """Requests without X-Request-Id get one generated."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    rid = resp.headers.get("X-Request-Id")
    assert rid is not None
    assert len(rid) == 8


def test_request_id_preserved(client):
    """Client-supplied X-Request-Id is preserved."""
    resp = client.get("/api/v1/health", headers={"X-Request-Id": "custom42"})
    assert resp.headers["X-Request-Id"] == "custom42"


def test_request_id_unique_per_request(client):
    """Each request gets a unique ID."""
    ids = set()
    for _ in range(5):
        resp = client.get("/api/v1/health")
        ids.add(resp.headers["X-Request-Id"])
    assert len(ids) == 5


def test_get_logger_returns_logger():
    """get_logger returns a stdlib Logger."""
    from kryon.server.logging_config import get_logger

    log = get_logger("test.module")
    assert isinstance(log, logging.Logger)
    assert log.name == "test.module"
