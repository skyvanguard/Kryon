"""Tests for run endpoints."""


def test_get_run_not_found(client):
    resp = client.get("/api/runs/nonexistent")
    assert resp.status_code == 404


def test_cancel_run_not_found(client):
    resp = client.delete("/api/runs/nonexistent")
    assert resp.status_code == 404


def test_create_run_invalid_agent(client):
    resp = client.post("/api/runs", json={
        "agent_key": "nonexistent_agent_xyz",
        "input": "hello",
    })
    assert resp.status_code == 404
