"""Tests for health endpoint."""


def test_health_returns_ok(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"
    assert data["agents_count"] > 0


def test_health_no_auth_required(auth_client):
    # Health endpoint should work without auth header
    resp = auth_client.get("/api/v1/health")
    assert resp.status_code == 200


def test_readiness_check(client):
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "uptime_seconds" in data
    assert "checks" in data
    assert "database" in data["checks"]
    assert data["checks"]["database"]["status"] in ("healthy", "unhealthy")
