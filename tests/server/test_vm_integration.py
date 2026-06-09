"""Tests for VM integration API routes."""

import sys
from unittest.mock import patch

import pytest

# The import-file endpoint validates that the path lives under /workspace or
# /tmp (container import dirs). On Windows the pytest tmp_path is outside that
# allowlist, so the file-import tests only run on POSIX (and in Linux CI).
_skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32",
    reason="ImportFileRequest path allowlist is container-relative (/workspace, /tmp)",
)
from starlette.testclient import TestClient

from kryon.server import ServerConfig, create_app


@pytest.fixture
def client():
    """Create test client with auth disabled (empty api_keys)."""
    config = ServerConfig(api_keys=[])
    app = create_app(config)
    with TestClient(app) as c:
        yield c


def test_import_qualys_endpoint(client):
    """POST /api/v1/import/qualys returns 202 accepted."""
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/qualys",
            json={
                "api_url": "https://qualysapi.example.com",
                "api_key": "test-key-123",
                "scan_id": "scan-001",
                "auto_validate": False,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data
        assert data["status"] == "queued"


def test_import_tenable_endpoint(client):
    """POST /api/v1/import/tenable returns 202 accepted."""
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/tenable",
            json={
                "api_url": "https://cloud.tenable.com",
                "access_key": "ak-123",
                "secret_key": "sk-456",
                "auto_validate": False,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data


def test_import_rapid7_endpoint(client):
    """POST /api/v1/import/rapid7 returns 202 accepted."""
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/rapid7",
            json={
                "api_url": "https://insightvm.example.com",
                "api_key": "r7-key-789",
                "auto_validate": False,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data


@_skip_on_windows
def test_import_file_endpoint(client, tmp_path):
    """POST /api/v1/import/file accepts nmap XML."""
    nmap_xml = tmp_path / "scan.xml"
    nmap_xml.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/file",
            json={
                "file_path": str(nmap_xml),
                "source_type": "nmap",
                "auto_validate": False,
            },
        )
        assert resp.status_code == 202


def test_import_status_not_found(client):
    """GET /api/v1/import/{job_id} returns 404 for unknown job."""
    resp = client.get("/api/v1/import/nonexistent-job-123")
    assert resp.status_code == 404


def test_import_status_found(client):
    """GET /api/v1/import/{job_id} returns status for existing job."""
    from kryon.server.routes import vm_integration

    vm_integration._import_jobs["test-job-1"] = {
        "job_id": "test-job-1",
        "status": "completed",
        "source": "qualys",
        "findings_count": 5,
    }
    resp = client.get("/api/v1/import/test-job-1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    # Cleanup
    del vm_integration._import_jobs["test-job-1"]


def test_import_qualys_returns_source(client):
    """POST /api/v1/import/qualys response includes source field."""
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/qualys",
            json={
                "api_url": "https://qualysapi.example.com",
                "api_key": "test-key-123",
            },
        )
        data = resp.json()
        assert data["source"] == "qualys"


def test_import_tenable_returns_source(client):
    """POST /api/v1/import/tenable response includes source field."""
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/tenable",
            json={
                "api_url": "https://cloud.tenable.com",
                "access_key": "ak-123",
                "secret_key": "sk-456",
            },
        )
        data = resp.json()
        assert data["source"] == "tenable"


@_skip_on_windows
def test_import_file_nuclei_source(client, tmp_path):
    """POST /api/v1/import/file with nuclei type returns nuclei source."""
    jsonl_file = tmp_path / "results.jsonl"
    jsonl_file.write_text('{"info":{"severity":"high"}}\n')
    with patch("kryon.server.routes.vm_integration._run_import") as mock_run:
        resp = client.post(
            "/api/v1/import/file",
            json={
                "file_path": str(jsonl_file),
                "source_type": "nuclei",
                "auto_validate": False,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["source"] == "nuclei"
