"""Tests for global error handler middleware."""

import pytest
from fastapi import APIRouter, FastAPI
from starlette.testclient import TestClient

from kryon.server import ServerConfig, create_app
from kryon.server.logging_config import setup_logging
from kryon.server.middleware.error_handler import global_exception_handler
from kryon.server.middleware.request_id import RequestIdMiddleware


def _make_minimal_crash_app(debug: bool = False):
    """Create a minimal FastAPI app with the error handler and a crashing route."""
    setup_logging(debug=debug)
    app = FastAPI()
    app.add_exception_handler(Exception, global_exception_handler)
    app.add_middleware(RequestIdMiddleware)

    @app.get("/api/v1/test-crash")
    async def crash():
        raise RuntimeError("boom")

    @app.get("/api/v1/ok")
    async def ok():
        return {"status": "ok"}

    return app


def test_unhandled_exception_returns_500(monkeypatch):
    monkeypatch.setenv("KRYON_DEBUG", "0")
    app = _make_minimal_crash_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/api/v1/test-crash")
    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "Internal server error"
    assert "request_id" in body
    assert "traceback" not in body


def test_debug_mode_includes_error_type(monkeypatch):
    monkeypatch.setenv("KRYON_DEBUG", "1")
    app = _make_minimal_crash_app(debug=True)
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/api/v1/test-crash")
    assert resp.status_code == 500
    body = resp.json()
    assert "traceback" not in body  # traceback must never leak to client
    assert body["error_type"] == "RuntimeError"


def test_error_response_has_request_id():
    app = _make_minimal_crash_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/api/v1/test-crash")
    body = resp.json()
    assert len(body["request_id"]) == 8


def test_normal_routes_unaffected(client):
    """Non-crashing routes still work fine."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200


def test_http_exceptions_pass_through(client):
    """HTTPExceptions (like 404) are not caught by the global handler."""
    resp = client.get("/api/v1/runs/nonexistent")
    assert resp.status_code == 404
    body = resp.json()
    assert "detail" in body
