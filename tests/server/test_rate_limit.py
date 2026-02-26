"""Tests for API rate limiting middleware."""

import pytest
from starlette.testclient import TestClient

from kryon.server import ServerConfig, create_app


@pytest.fixture
def limited_client():
    """Client with very low rate limit for testing."""
    app = create_app(ServerConfig(api_keys=[], rate_limit_rpm=5))
    with TestClient(app) as c:
        yield c


def test_rate_limit_headers_present(client):
    """Rate limit headers should be present on responses."""
    resp = client.get("/api/agents")
    assert "X-RateLimit-Limit" in resp.headers
    assert "X-RateLimit-Remaining" in resp.headers


def test_health_excluded_from_rate_limit(limited_client):
    """Health endpoint should not be rate limited."""
    for _ in range(10):
        resp = limited_client.get("/api/health")
        assert resp.status_code == 200


def test_rate_limit_enforced(limited_client):
    """After exceeding the limit, should get 429."""
    for _ in range(5):
        resp = limited_client.get("/api/agents")
        assert resp.status_code == 200

    resp = limited_client.get("/api/agents")
    assert resp.status_code == 429
    assert resp.json()["detail"] == "Too many requests"
    assert "Retry-After" in resp.headers


def test_rate_limit_remaining_decrements(limited_client):
    """X-RateLimit-Remaining should decrement with each request."""
    resp = limited_client.get("/api/agents")
    remaining = int(resp.headers["X-RateLimit-Remaining"])
    assert remaining == 4

    resp = limited_client.get("/api/agents")
    remaining2 = int(resp.headers["X-RateLimit-Remaining"])
    assert remaining2 == 3
