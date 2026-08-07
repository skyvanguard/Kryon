"""Tests for onboarding API routes."""

import pytest


def test_start_onboarding(client):
    resp = client.post(
        "/api/v1/onboarding/start",
        json={"client_name": "Acme Corp", "contact": "admin@acme.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert "client_id" in data


def test_update_step(client):
    start = client.post("/api/v1/onboarding/start", json={"client_name": "TestCo"})
    sid = start.json()["session_id"]
    resp = client.put(
        f"/api/v1/onboarding/{sid}/step",
        json={"step": 2, "data": {"targets": ["10.0.0.1"]}},
    )
    assert resp.status_code == 200
    assert resp.json()["current_step"] == 2


def test_get_session(client):
    start = client.post("/api/v1/onboarding/start", json={"client_name": "TestCo"})
    sid = start.json()["session_id"]
    resp = client.get(f"/api/v1/onboarding/{sid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == sid


def test_get_session_not_found(client):
    resp = client.get("/api/v1/onboarding/nonexistent-session")
    assert resp.status_code == 404


def test_complete_onboarding(client):
    start = client.post("/api/v1/onboarding/start", json={"client_name": "TestCo"})
    sid = start.json()["session_id"]
    resp = client.post(f"/api/v1/onboarding/{sid}/complete")
    assert resp.status_code == 200
    data = resp.json()
    assert data["completed"] is True


def test_import_assets_json(client):
    start = client.post("/api/v1/onboarding/start", json={"client_name": "TestCo"})
    cid = start.json()["client_id"]
    resp = client.post(
        "/api/v1/onboarding/import-assets",
        json={
            "client_id": cid,
            "format": "json",
            "data": '[{"hostname": "srv1", "ip": "10.0.0.1"}]',
        },
    )
    assert resp.status_code == 200
    assert resp.json()["imported"] >= 0


def test_validate_scope(client):
    resp = client.post(
        "/api/v1/onboarding/validate-scope",
        json={"targets": ["127.0.0.1"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert "total" in data
    assert data["total"] == 1


def test_validate_scope_empty(client):
    resp = client.post("/api/v1/onboarding/validate-scope", json={"targets": []})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0
