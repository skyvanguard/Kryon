"""Tests for health endpoint."""


def test_health_returns_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"
    assert data["agents_count"] > 0


def test_health_no_auth_required(auth_client):
    # Health endpoint should work without auth header
    resp = auth_client.get("/api/health")
    assert resp.status_code == 200
