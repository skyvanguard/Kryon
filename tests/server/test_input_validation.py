"""Tests for input validation bounds on API models."""

import pytest


def test_run_input_max_length(client):
    """RunRequest.input rejects inputs over 50000 chars."""
    resp = client.post("/api/v1/runs", json={
        "agent_key": "recon_scout",
        "input": "x" * 50001,
    })
    assert resp.status_code == 422


def test_run_input_within_limit(client):
    """RunRequest.input accepts inputs within limit (agent may not exist, but validation passes)."""
    resp = client.post("/api/v1/runs", json={
        "agent_key": "recon_scout",
        "input": "x" * 100,
    })
    # 404 = agent not found, but 422 would mean validation failed
    assert resp.status_code != 422


def test_engagement_targets_max_length(client):
    """CreateEngagementRequest.targets rejects lists over 50 items."""
    resp = client.post("/api/v1/engagements", json={
        "client_name": "TestCorp",
        "targets": [f"10.0.0.{i}" for i in range(51)],
    })
    assert resp.status_code == 422


def test_engagement_client_name_max_length(client):
    """CreateEngagementRequest.client_name rejects names over 200 chars."""
    resp = client.post("/api/v1/engagements", json={
        "client_name": "A" * 201,
        "targets": ["10.0.0.1"],
    })
    assert resp.status_code == 422


def test_knowledge_query_empty_question(client):
    """KnowledgeQueryRequest rejects empty question."""
    resp = client.post("/api/v1/knowledge/query", json={
        "question": "",
    })
    assert resp.status_code == 422


def test_knowledge_query_top_k_bounds(client):
    """KnowledgeQueryRequest rejects top_k outside 1-50."""
    resp = client.post("/api/v1/knowledge/query", json={
        "question": "test",
        "top_k": 0,
    })
    assert resp.status_code == 422

    resp = client.post("/api/v1/knowledge/query", json={
        "question": "test",
        "top_k": 51,
    })
    assert resp.status_code == 422
