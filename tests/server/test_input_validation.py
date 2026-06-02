"""Tests for input validation bounds on API models."""

import pytest


def test_run_input_max_length(client):
    """RunRequest.input rejects inputs over 50000 chars."""
    resp = client.post(
        "/api/v1/runs",
        json={
            "agent_key": "recon_scout",
            "input": "x" * 50001,
        },
    )
    assert resp.status_code == 422


def test_run_input_within_limit(client, monkeypatch):
    """RunRequest.input accepts inputs within limit — validation passes (not 422).
    v2.x: any agent_key resolves to the unified agent (no 404 path), so we mock
    the run and assert the request wasn't rejected by validation. Was asserting
    404, stale since the unified-only migration."""
    from types import SimpleNamespace

    from kryon.sdk.agents import Runner

    async def _ok(*args, **kwargs):
        return SimpleNamespace(
            final_output="ok",
            last_agent=SimpleNamespace(name="Kryon"),
            raw_responses=[],
            to_input_list=lambda: [],
        )

    monkeypatch.setattr(Runner, "run", _ok)

    resp = client.post(
        "/api/v1/runs",
        json={
            "agent_key": "nonexistent_agent_for_test",
            "input": "x" * 100,
        },
    )
    assert resp.status_code != 422  # validation passed
    assert resp.status_code == 200


def test_engagement_targets_max_length(client):
    """CreateEngagementRequest.targets rejects lists over 50 items."""
    resp = client.post(
        "/api/v1/engagements",
        json={
            "client_name": "TestCorp",
            "targets": [f"10.0.0.{i}" for i in range(51)],
        },
    )
    assert resp.status_code == 422


def test_engagement_client_name_max_length(client):
    """CreateEngagementRequest.client_name rejects names over 200 chars."""
    resp = client.post(
        "/api/v1/engagements",
        json={
            "client_name": "A" * 201,
            "targets": ["10.0.0.1"],
        },
    )
    assert resp.status_code == 422


def test_knowledge_query_empty_question(client):
    """KnowledgeQueryRequest rejects empty question."""
    resp = client.post(
        "/api/v1/knowledge/query",
        json={
            "question": "",
        },
    )
    assert resp.status_code == 422


def test_knowledge_query_top_k_bounds(client):
    """KnowledgeQueryRequest rejects top_k outside 1-50."""
    resp = client.post(
        "/api/v1/knowledge/query",
        json={
            "question": "test",
            "top_k": 0,
        },
    )
    assert resp.status_code == 422

    resp = client.post(
        "/api/v1/knowledge/query",
        json={
            "question": "test",
            "top_k": 51,
        },
    )
    assert resp.status_code == 422
