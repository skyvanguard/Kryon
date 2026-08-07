"""Tests for report settings API routes."""

import pytest


def test_list_templates(client):
    resp = client.get("/api/v1/reports/templates")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "name" in data[0]


def test_save_branding(client):
    resp = client.post(
        "/api/v1/reports/branding",
        json={
            "client_id": "c1",
            "company_name": "Acme Corp",
            "logo_url": "https://example.com/logo.png",
            "primary_color": "#FF0000",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert data["client_id"] == "c1"


def test_get_branding(client):
    client.post(
        "/api/v1/reports/branding",
        json={"client_id": "c2", "company_name": "TestCo"},
    )
    resp = client.get("/api/v1/reports/branding/c2")
    assert resp.status_code == 200
    data = resp.json()
    assert data["company_name"] == "TestCo"


def test_get_branding_not_found(client):
    resp = client.get("/api/v1/reports/branding/nonexistent")
    assert resp.status_code == 404


def test_update_branding(client):
    client.post(
        "/api/v1/reports/branding",
        json={"client_id": "c3", "company_name": "Initial"},
    )
    resp = client.post(
        "/api/v1/reports/branding",
        json={"client_id": "c3", "company_name": "Updated", "primary_color": "#FFFFFF"},
    )
    assert resp.status_code == 200
    # Verify update persisted
    get_resp = client.get("/api/v1/reports/branding/c3")
    assert get_resp.json()["company_name"] == "Updated"
