"""Tests for usage endpoints."""


def test_get_usage_summary(client):
    resp = client.get("/api/usage")
    assert resp.status_code == 200
    data = resp.json()
    assert "global_totals" in data


def test_get_model_usage(client):
    resp = client.get("/api/usage/models")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_get_daily_usage(client):
    resp = client.get("/api/usage/daily")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
