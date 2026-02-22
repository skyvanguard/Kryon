"""Tests for session endpoints."""


def test_create_session(client):
    # Get a valid agent key first
    agents = client.get("/api/agents").json()
    key = agents[0]["key"]

    resp = client.post("/api/sessions", json={"agent_key": key})
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["agent_key"] == key


def test_create_session_invalid_agent(client):
    resp = client.post("/api/sessions", json={"agent_key": "nonexistent_xyz"})
    assert resp.status_code == 404


def test_list_sessions(client):
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
