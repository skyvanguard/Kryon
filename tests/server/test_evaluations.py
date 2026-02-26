"""Tests for evaluation metrics API endpoints."""

from unittest.mock import MagicMock, patch

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
    return {"Authorization": "Bearer test-key"}


class TestGetMetrics:
    def test_get_metrics_empty(self, client, headers):
        with (
            patch("kryon.evaluation.dashboard_metrics.DashboardMetrics") as MockMetrics,
        ):
            MockMetrics.return_value.compute.return_value = {"total": 0}
            resp = client.get("/api/v1/evaluations/metrics", headers=headers)
            assert resp.status_code == 200

    def test_get_metrics_invalid_json(self, client, headers):
        resp = client.get(
            "/api/v1/evaluations/metrics?findings_json=bad{{json",
            headers=headers,
        )
        assert resp.status_code == 400
        assert "Malformed" in resp.json()["detail"]


class TestCompareScans:
    def test_compare_scans_empty(self, client, headers):
        with (
            patch("kryon.evaluation.comparator.ScanComparator") as MockComp,
        ):
            mock_result = MagicMock()
            mock_result.model_dump.return_value = {"new": [], "fixed": [], "unchanged": []}
            MockComp.return_value.compare.return_value = mock_result
            resp = client.get("/api/v1/evaluations/compare", headers=headers)
            assert resp.status_code == 200

    def test_compare_scans_invalid_json(self, client, headers):
        resp = client.get(
            "/api/v1/evaluations/compare?before_json=invalid",
            headers=headers,
        )
        assert resp.status_code == 400


class TestListProfiles:
    def test_list_profiles(self, client, headers):
        with patch("kryon.server.routes.evaluations.list_profiles", return_value=[]):
            resp = client.get("/api/v1/profiles", headers=headers)
            assert resp.status_code == 200
            assert isinstance(resp.json(), list)
