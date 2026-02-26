"""Tests for auto-scan API endpoints."""

import pytest


class TestAutoScanEndpoints:
    def test_start_auto_scan(self, client):
        """POST /scans/auto should start a scan and return scan_id."""
        resp = client.post(
            "/api/v1/scans/auto",
            json={
                "targets": ["192.168.1.1"],
                "profile": "quick",
                "client_id": "test-client",
                "max_time_hours": 0.1,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "started"
        assert "message" in data

    def test_start_auto_scan_missing_targets(self, client):
        """POST /scans/auto without targets should fail validation."""
        resp = client.post("/api/v1/scans/auto", json={"profile": "quick"})
        assert resp.status_code == 422  # Pydantic validation error

    def test_get_auto_scan_status(self, client):
        """GET /scans/auto/{scan_id} should return scan status."""
        # First start a scan
        resp = client.post(
            "/api/v1/scans/auto",
            json={"targets": ["10.0.0.1"], "max_time_hours": 0.1},
        )
        scan_id = resp.json()["scan_id"]

        # Then check status
        resp = client.get(f"/api/v1/scans/auto/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert "status" in data
        assert "findings_count" in data
        assert "elapsed_seconds" in data

    def test_get_auto_scan_status_not_found(self, client):
        """GET /scans/auto/{bad_id} should return 404."""
        resp = client.get("/api/v1/scans/auto/nonexistent")
        assert resp.status_code == 404

    def test_get_auto_scan_findings(self, client):
        """GET /scans/auto/{scan_id}/findings should return list."""
        resp = client.post(
            "/api/v1/scans/auto",
            json={"targets": ["10.0.0.1"], "max_time_hours": 0.1},
        )
        scan_id = resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/auto/{scan_id}/findings")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_auto_scan_findings_not_found(self, client):
        resp = client.get("/api/v1/scans/auto/nonexistent/findings")
        assert resp.status_code == 404

    def test_cancel_auto_scan(self, client):
        """DELETE /scans/auto/{scan_id} should cancel the scan."""
        resp = client.post(
            "/api/v1/scans/auto",
            json={"targets": ["10.0.0.1"], "max_time_hours": 0.1},
        )
        scan_id = resp.json()["scan_id"]

        resp = client.delete(f"/api/v1/scans/auto/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "cancelled"

    def test_cancel_nonexistent_scan(self, client):
        resp = client.delete("/api/v1/scans/auto/nonexistent")
        assert resp.status_code == 404

    def test_auto_scan_with_all_options(self, client):
        """POST /scans/auto with all options."""
        resp = client.post(
            "/api/v1/scans/auto",
            json={
                "targets": ["192.168.1.0/30", "10.10.10.5"],
                "profile": "enterprise_standard",
                "client_id": "acme-corp",
                "max_time_hours": 2.0,
                "stealth_level": "high",
                "output_format": "html",
                "compliance_frameworks": ["pci-dss"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "started"


class TestAutoScanSSE:
    def test_stream_endpoint_exists(self, client):
        """GET /scans/auto/{scan_id}/stream should exist for valid scans."""
        resp = client.post(
            "/api/v1/scans/auto",
            json={"targets": ["10.0.0.1"], "max_time_hours": 0.1},
        )
        scan_id = resp.json()["scan_id"]

        # Note: TestClient may not fully support SSE streaming,
        # but we can verify the endpoint responds
        resp = client.get(f"/api/v1/scans/auto/{scan_id}/stream")
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

    def test_stream_not_found(self, client):
        resp = client.get("/api/v1/scans/auto/nonexistent/stream")
        assert resp.status_code == 404
