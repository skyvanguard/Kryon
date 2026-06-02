"""Tests for session endpoints."""


def test_create_session(client):
    # Get a valid agent key first
    agents = client.get("/api/v1/agents").json()
    key = agents[0]["key"]

    resp = client.post("/api/v1/sessions", json={"agent_key": key})
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["agent_key"] == key


def test_create_session_unknown_agent_resolves_to_unified(client):
    """v2.x unified-only: any agent_key resolves to the unified Kryon agent
    (PR #57 removed the 404-on-unknown-agent path), so a session is created.
    Was test_create_session_invalid_agent asserting 404."""
    resp = client.post("/api/v1/sessions", json={"agent_key": "nonexistent_xyz"})
    assert resp.status_code == 200
    assert "session_id" in resp.json()


def test_list_sessions(client):
    resp = client.get("/api/v1/sessions")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
