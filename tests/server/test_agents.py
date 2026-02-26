"""Tests for agent endpoints."""


def test_list_agents(client):
    resp = client.get("/api/v1/agents")
    assert resp.status_code == 200
    agents = resp.json()
    assert isinstance(agents, list)
    assert len(agents) > 0
    # Each agent has required fields
    for agent in agents:
        assert "key" in agent
        assert "name" in agent


def test_get_agent_detail(client):
    # First get list to find a valid key
    agents = client.get("/api/v1/agents").json()
    key = agents[0]["key"]

    resp = client.get(f"/api/v1/agents/{key}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["key"] == key
    assert "tools" in detail
    assert "handoffs" in detail


def test_get_agent_not_found(client):
    resp = client.get("/api/v1/agents/nonexistent_agent_xyz")
    assert resp.status_code == 404


def test_agents_require_auth(auth_client):
    resp = auth_client.get("/api/v1/agents")
    assert resp.status_code == 401

    resp = auth_client.get("/api/v1/agents", headers={"X-API-Key": "test-key-123"})
    assert resp.status_code == 200
