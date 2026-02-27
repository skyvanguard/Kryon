"""Tests for engagement API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from kryon.server.app import create_app
from kryon.server.config import ServerConfig


@pytest.fixture
def client():
    config = ServerConfig(api_keys=["test-key"])
    app = create_app(config)
    return TestClient(app)


@pytest.fixture
def headers():
    return {"Authorization": "Bearer test-key", "Content-Type": "application/json"}


class TestCreateEngagement:
    def test_create_engagement(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            from kryon.engagements.models import Engagement

            eng = Engagement(client_name="TestCorp", targets=["10.0.0.1"])
            mock_mgr.return_value.create_engagement = AsyncMock(return_value=eng)

            resp = client.post(
                "/api/v1/engagements",
                json={"client_name": "TestCorp", "targets": ["10.0.0.1"]},
                headers=headers,
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["id"] == eng.id
            assert data["status"] == "created"

    def test_create_requires_client_name(self, client, headers):
        resp = client.post(
            "/api/v1/engagements",
            json={"targets": ["10.0.0.1"]},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_create_requires_targets(self, client, headers):
        resp = client.post(
            "/api/v1/engagements",
            json={"client_name": "Test"},
            headers=headers,
        )
        assert resp.status_code == 422


class TestListEngagements:
    def test_list_engagements(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            from kryon.engagements.models import Engagement

            mock_mgr.return_value.store.list_engagements.return_value = [
                Engagement(client_name="A", targets=["1.1.1.1"]),
                Engagement(client_name="B", targets=["2.2.2.2"]),
            ]

            resp = client.get("/api/v1/engagements", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 2


class TestGetEngagement:
    def test_get_engagement(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            from kryon.engagements.models import Engagement

            eng = Engagement(client_name="Test", targets=["10.0.0.1"])
            mock_mgr.return_value.store.get_engagement.return_value = eng
            mock_mgr.return_value.store.get_engagement_phases.return_value = []

            resp = client.get(f"/api/v1/engagements/{eng.id}", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["client_name"] == "Test"
            assert "phases" in data

    def test_get_not_found(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            mock_mgr.return_value.store.get_engagement.return_value = None

            resp = client.get("/api/v1/engagements/nonexistent", headers=headers)
            assert resp.status_code == 404


class TestPauseResume:
    def test_pause(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            from kryon.engagements.models import Engagement, EngagementStatus

            eng = Engagement(client_name="Test", targets=["10.0.0.1"], status=EngagementStatus.ACTIVE)
            mock_mgr.return_value.store.get_engagement.return_value = eng
            mock_mgr.return_value.pause_engagement = AsyncMock()

            resp = client.post(f"/api/v1/engagements/{eng.id}/pause", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["status"] == "paused"

    def test_resume(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            from kryon.engagements.models import Engagement, EngagementStatus

            eng = Engagement(client_name="Test", targets=["10.0.0.1"], status=EngagementStatus.PAUSED)
            mock_mgr.return_value.store.get_engagement.return_value = eng
            mock_mgr.return_value.resume_engagement = AsyncMock()

            resp = client.post(f"/api/v1/engagements/{eng.id}/resume", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["status"] == "active"


class TestCancelEngagement:
    def test_cancel(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            from kryon.engagements.models import Engagement

            eng = Engagement(client_name="Test", targets=["10.0.0.1"])
            mock_mgr.return_value.store.get_engagement.return_value = eng
            mock_mgr.return_value.cancel_engagement = AsyncMock()

            resp = client.delete(f"/api/v1/engagements/{eng.id}", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["status"] == "cancelled"

    def test_cancel_not_found(self, client, headers):
        with patch("kryon.server.routes.engagements.get_engagement_manager") as mock_mgr:
            mock_mgr.return_value.store.get_engagement.return_value = None

            resp = client.delete("/api/v1/engagements/nonexistent", headers=headers)
            assert resp.status_code == 404
