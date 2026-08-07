"""Tests for knowledge base API endpoints."""

import importlib

import pytest

_has_sentence_transformers = importlib.util.find_spec("sentence_transformers") is not None


class TestKnowledgeStats:
    def test_knowledge_stats_returns_ok(self, client):
        resp = client.get("/api/v1/knowledge/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_documents" in data
        assert "llm_configured" in data
        assert "llm_model" in data


class TestKnowledgeQuery:
    def test_query_requires_question(self, client):
        resp = client.post("/api/v1/knowledge/query", json={})
        assert resp.status_code == 422

    def test_query_returns_result(self, client):
        resp = client.post(
            "/api/v1/knowledge/query",
            json={"question": "SQL injection", "use_llm": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["question"] == "SQL injection"
        assert "sources" in data
        assert "num_sources" in data


class TestKnowledgeAdd:
    @pytest.mark.skipif(not _has_sentence_transformers, reason="sentence_transformers not installed")
    def test_add_document(self, client):
        resp = client.post(
            "/api/v1/knowledge/add",
            json={
                "content": "Test vulnerability description for CVE-2024-0001",
                "source": "test",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "doc_id" in data
        assert len(data["doc_id"]) > 0

    def test_add_requires_content(self, client):
        resp = client.post("/api/v1/knowledge/add", json={"source": "test"})
        assert resp.status_code == 422

    def test_add_requires_source(self, client):
        resp = client.post("/api/v1/knowledge/add", json={"content": "test data"})
        assert resp.status_code == 422


class TestKnowledgeScrape:
    def test_start_scrape(self, client):
        resp = client.post(
            "/api/v1/knowledge/scrape",
            json={"sources": ["intelligence"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "task_id" in data
        assert data["status"] == "started"

    def test_scrape_status_not_found(self, client):
        resp = client.get("/api/v1/knowledge/scrape/nonexistent")
        assert resp.status_code == 404
