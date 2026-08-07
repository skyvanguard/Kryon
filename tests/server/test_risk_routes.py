"""Tests for risk analysis API routes."""

import pytest


def test_risk_overview_empty(client):
    resp = client.get("/api/v1/risk/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_score" in data


def test_risk_overview_with_client(client):
    resp = client.get("/api/v1/risk/overview?client_id=test-client")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_score" in data


def test_risky_assets(client):
    resp = client.get("/api/v1/risk/assets")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


def test_risky_assets_with_limit(client):
    resp = client.get("/api/v1/risk/assets?limit=5")
    assert resp.status_code == 200
    assert "items" in resp.json()


def test_risk_trend(client):
    resp = client.get("/api/v1/risk/trend?days=30")
    assert resp.status_code == 200
    data = resp.json()
    assert "data_points" in data
    assert data["days"] == 30
