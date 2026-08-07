"""Tests for CORS hardening and security headers."""

import pytest

from kryon.server import ServerConfig, create_app


@pytest.fixture
def strict_client():
    """Client with non-debug (restrictive) CORS."""
    app = create_app(ServerConfig(api_keys=[], debug=False))
    from starlette.testclient import TestClient

    with TestClient(app) as c:
        yield c


def test_security_headers_present(client):
    """All security headers must be present on every response."""
    resp = client.get("/api/v1/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers["Permissions-Policy"]


def test_no_hsts_without_https(client):
    """HSTS should NOT be present when HTTPS is disabled."""
    resp = client.get("/api/v1/health")
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_with_https():
    """HSTS should be present when HTTPS is enabled."""
    app = create_app(ServerConfig(api_keys=[], https_enabled=True))
    from starlette.testclient import TestClient

    with TestClient(app) as c:
        resp = c.get("/api/v1/health")
    assert "Strict-Transport-Security" in resp.headers
    assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]


def test_cors_restrictive_default(strict_client):
    """Default CORS should NOT allow arbitrary origins."""
    resp = strict_client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://evil.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Should not have Access-Control-Allow-Origin for evil.com
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    assert acao != "http://evil.com"
    assert acao != "*"
