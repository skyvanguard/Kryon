"""Tests for attack path analysis API routes."""

import pytest


def test_analyze_empty(client):
    resp = client.post("/api/v1/attack-paths/analyze", json={"finding_ids": []})
    assert resp.status_code == 200
    data = resp.json()
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["chains"] == []


def test_analyze_nonexistent_ids(client):
    resp = client.post("/api/v1/attack-paths/analyze", json={"finding_ids": ["nope1", "nope2"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["nodes"] == []


def test_client_attack_paths_empty(client):
    resp = client.get("/api/v1/attack-paths/client/no-such-client")
    assert resp.status_code == 200
    data = resp.json()
    assert data["nodes"] == []


def test_client_chains_empty(client):
    resp = client.get("/api/v1/attack-paths/chains/no-such-client")
    assert resp.status_code == 200
    data = resp.json()
    assert "chains" in data
    assert data["total"] == 0
