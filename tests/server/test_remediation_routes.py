"""Tests for remediation API routes."""

import pytest


def test_assign_not_found(client):
    resp = client.put(
        "/api/v1/remediation/findings/nonexistent/assign",
        json={"assigned_to": "a@b.com"},
    )
    assert resp.status_code == 404


def test_add_note_not_found(client):
    resp = client.post(
        "/api/v1/remediation/findings/nonexistent/note",
        json={"note": "test"},
    )
    assert resp.status_code == 404


def test_schedule_retest_not_found(client):
    resp = client.post(
        "/api/v1/remediation/findings/nonexistent/retest",
        json={"agent_key": "vuln_hunter"},
    )
    assert resp.status_code == 404


def test_list_overdue(client):
    resp = client.get("/api/v1/remediation/overdue")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


def test_get_metrics(client):
    resp = client.get("/api/v1/remediation/metrics")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


def test_get_history_empty(client):
    resp = client.get("/api/v1/remediation/findings/nonexistent/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    assert len(resp.json()) == 0


def test_assign_validation(client):
    resp = client.put(
        "/api/v1/remediation/findings/test/assign",
        json={},
    )
    assert resp.status_code == 422  # Missing required assigned_to
