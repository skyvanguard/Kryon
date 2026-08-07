"""Tests for notification API routes."""

import pytest


def test_create_channel(client):
    resp = client.post(
        "/api/v1/notifications/channels",
        json={"name": "Test Email", "channel_type": "email", "config_json": {"to": "a@b.com"}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert data["name"] == "Test Email"
    assert data["channel_type"] == "email"


def test_list_channels(client):
    client.post(
        "/api/v1/notifications/channels",
        json={"name": "Slack", "channel_type": "slack"},
    )
    resp = client.get("/api/v1/notifications/channels")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    assert len(resp.json()) >= 1


def test_update_channel(client):
    create = client.post(
        "/api/v1/notifications/channels",
        json={"name": "Original", "channel_type": "email"},
    )
    cid = create.json()["id"]
    resp = client.put(f"/api/v1/notifications/channels/{cid}", json={"name": "Updated", "enabled": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Updated"


def test_update_channel_not_found(client):
    resp = client.put("/api/v1/notifications/channels/nope", json={"name": "X"})
    assert resp.status_code == 404


def test_delete_channel(client):
    create = client.post(
        "/api/v1/notifications/channels",
        json={"name": "To Delete", "channel_type": "webhook"},
    )
    cid = create.json()["id"]
    resp = client.delete(f"/api/v1/notifications/channels/{cid}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


def test_delete_channel_not_found(client):
    resp = client.delete("/api/v1/notifications/channels/nope")
    assert resp.status_code == 404


def test_create_rule(client):
    resp = client.post(
        "/api/v1/notifications/rules",
        json={"event_type": "new_critical_finding", "severity_filter": "critical"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert data["event_type"] == "new_critical_finding"


def test_list_rules(client):
    client.post("/api/v1/notifications/rules", json={"event_type": "scan_complete"})
    resp = client.get("/api/v1/notifications/rules")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_delete_rule(client):
    create = client.post("/api/v1/notifications/rules", json={"event_type": "test"})
    rid = create.json()["id"]
    resp = client.delete(f"/api/v1/notifications/rules/{rid}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


def test_delete_rule_not_found(client):
    resp = client.delete("/api/v1/notifications/rules/nope")
    assert resp.status_code == 404


def test_get_notification_log(client):
    resp = client.get("/api/v1/notifications/log")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "offset" in data


def test_test_channel_not_found(client):
    resp = client.post("/api/v1/notifications/test/nonexistent")
    assert resp.status_code == 404
