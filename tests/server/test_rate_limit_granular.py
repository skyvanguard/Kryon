"""Tests for granular rate limiting per endpoint bucket."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from kryon.server.middleware.rate_limit import (
    _ENDPOINT_LIMITS,
    RateLimitMiddleware,
    _extract_user_id,
    _get_bucket,
)


def test_get_bucket_auth():
    bucket, limit = _get_bucket("/api/v1/auth/login")
    assert bucket == "/api/v1/auth/"
    assert limit == 10


def test_get_bucket_default():
    bucket, limit = _get_bucket("/api/v1/clients")
    assert bucket == "default"
    assert limit is None


def test_get_bucket_scans():
    bucket, limit = _get_bucket("/api/v1/scans/abc123")
    assert bucket == "/api/v1/scans/"
    assert limit == 15


def test_extract_user_id_no_header():
    from starlette.requests import Request

    scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
    req = Request(scope)
    assert _extract_user_id(req) is None


def test_rate_limit_applies_endpoint_specific(tmp_path, monkeypatch):
    """Auth endpoint should be limited to 10 RPM, not the global default."""
    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/api/v1/auth/login")
    async def login():
        return {"ok": True}

    app.add_middleware(RateLimitMiddleware, rpm=1000)
    client = TestClient(app)

    # First 10 should succeed
    for _ in range(10):
        resp = client.get("/api/v1/auth/login")
        assert resp.status_code == 200

    # 11th should be rate limited
    resp = client.get("/api/v1/auth/login")
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After")
