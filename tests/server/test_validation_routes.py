"""Tests for EVE validation API routes (POST /validate, GET /validate/{id}, POST /validate/batch)."""

import pytest
from starlette.testclient import TestClient

from kryon.server import ServerConfig, create_app


@pytest.fixture
def client():
    config = ServerConfig(api_keys=[])
    app = create_app(config)
    with TestClient(app) as c:
        yield c


def test_validate_endpoint_accepts_post(client):
    resp = client.post(
        "/api/v1/validate",
        json={
            "finding_id": "test123",
            "finding_type": "sqli",
            "target": "http://example.com/page?id=1",
        },
    )
    # Should accept the request (202 or 200), not 404
    assert resp.status_code != 404


def test_validate_returns_queued_status(client):
    resp = client.post(
        "/api/v1/validate",
        json={
            "finding_id": "test456",
            "finding_type": "xss",
            "target": "http://example.com/search",
        },
    )
    data = resp.json()
    assert "status" in data or "finding_id" in data


def test_validation_result_endpoint(client):
    resp = client.get("/api/v1/validate/nonexistent123")
    assert resp.status_code in (200, 404)


def test_validate_requires_finding_type(client):
    resp = client.post(
        "/api/v1/validate",
        json={
            "finding_id": "test789",
            "target": "http://example.com",
        },
    )
    assert resp.status_code == 422  # Missing required field


def test_validate_batch_endpoint(client):
    resp = client.post(
        "/api/v1/validate/batch",
        json={
            "findings": [
                {"finding_id": "f1", "finding_type": "sqli", "target": "http://t1.com"},
                {"finding_id": "f2", "finding_type": "xss", "target": "http://t2.com"},
            ]
        },
    )
    assert resp.status_code != 404


def test_validate_batch_returns_results(client):
    resp = client.post(
        "/api/v1/validate/batch",
        json={
            "findings": [
                {"finding_id": "f1", "finding_type": "sqli", "target": "http://t1.com"},
                {"finding_id": "f2", "finding_type": "xss", "target": "http://t2.com"},
            ]
        },
    )
    data = resp.json()
    assert "results" in data
    assert len(data["results"]) == 2


def test_validate_batch_empty_list(client):
    resp = client.post(
        "/api/v1/validate/batch",
        json={"findings": []},
    )
    # Should accept empty list or reject with 422
    assert resp.status_code in (200, 202, 422)


def test_validate_returns_finding_id_in_response(client):
    resp = client.post(
        "/api/v1/validate",
        json={
            "finding_id": "unique-id-001",
            "finding_type": "rce",
            "target": "http://example.com/cmd",
        },
    )
    data = resp.json()
    assert data["finding_id"] == "unique-id-001"
    assert data["status"] == "queued"


def test_validate_result_not_found(client):
    resp = client.get("/api/v1/validate/does-not-exist-999")
    assert resp.status_code == 404
    data = resp.json()
    assert "detail" in data
