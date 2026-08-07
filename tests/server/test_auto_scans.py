"""Tests for autonomous auto-scan API endpoints."""

import pytest
from fastapi.testclient import TestClient

from kryon.server.app import create_app
from kryon.server.config import ServerConfig


@pytest.fixture
def client():
    config = ServerConfig(api_keys=["test-key"])
    app = create_app(config)
    # `with` runs the lifespan so configure_auth() actually populates the keys.
    with TestClient(app) as c:
        yield c


@pytest.fixture
def headers():
    return {"X-API-Key": "test-key"}


class TestAutoScanNotFound:
    def test_auto_scan_not_found(self, client, headers):
        resp = client.get("/api/v1/scans/auto/nonexistent", headers=headers)
        assert resp.status_code == 404

    def test_cancel_auto_scan_not_found(self, client, headers):
        resp = client.delete("/api/v1/scans/auto/nonexistent", headers=headers)
        assert resp.status_code == 404

    def test_auto_scan_findings_not_found(self, client, headers):
        resp = client.get("/api/v1/scans/auto/nonexistent/findings", headers=headers)
        assert resp.status_code == 404

    def test_auto_scan_stream_not_found(self, client, headers):
        resp = client.get("/api/v1/scans/auto/nonexistent/stream", headers=headers)
        assert resp.status_code == 404
