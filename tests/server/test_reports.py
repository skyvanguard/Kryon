"""Tests for report generation API endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from kryon.server.app import create_app
from kryon.server.config import ServerConfig


@pytest.fixture
def client():
    config = ServerConfig(api_keys=["test-key"])
    app = create_app(config)
    # `with` runs the lifespan so configure_auth() actually populates the keys.
    with TestClient(app) as c:
        yield c


@pytest.fixture
def headers():
    return {"X-API-Key": "test-key", "Content-Type": "application/json"}


class TestGenerateReport:
    def test_generate_report_html(self, client, headers):
        with (
            patch("kryon.server.routes.reports.json") as mock_json,
            patch("kryon.reporting.generator.ReportGenerator") as MockGen,
            patch("kryon.reporting.export.save_report") as mock_save,
        ):
            from pathlib import Path

            mock_json.loads.return_value = []
            gen_instance = MockGen.return_value
            gen_instance.generate = AsyncMock(return_value="<html></html>")
            mock_save.return_value = Path("/tmp/report.html")

            resp = client.post(
                "/api/v1/reports",
                json={"findings_json": "[]", "client_name": "Test"},
                headers=headers,
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["format"] == "html"

    def test_generate_report_invalid_json(self, client, headers):
        resp = client.post(
            "/api/v1/reports",
            json={"findings_json": "not-json{{{"},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "Malformed" in resp.json()["detail"]

    def test_generate_report_invalid_findings(self, client, headers):
        resp = client.post(
            "/api/v1/reports",
            json={"findings_json": '[{"bad_field": true}]'},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "Invalid finding" in resp.json()["detail"]

    def test_generate_report_pdf_not_available(self, client, headers):
        with (
            patch("kryon.reporting.generator.ReportGenerator") as MockGen,
        ):
            gen_instance = MockGen.return_value
            gen_instance.generate = AsyncMock(return_value="<html></html>")
            gen_instance.to_pdf = AsyncMock(side_effect=ImportError("weasyprint not installed"))

            resp = client.post(
                "/api/v1/reports",
                json={"findings_json": "[]", "format": "pdf"},
                headers=headers,
            )
            assert resp.status_code == 501

    def test_generate_report_empty_findings(self, client, headers):
        with (
            patch("kryon.reporting.generator.ReportGenerator") as MockGen,
            patch("kryon.reporting.export.save_report") as mock_save,
        ):
            from pathlib import Path

            gen_instance = MockGen.return_value
            gen_instance.generate = AsyncMock(return_value="<html>empty</html>")
            mock_save.return_value = Path("/tmp/empty_report.html")

            resp = client.post(
                "/api/v1/reports",
                json={"findings_json": "[]"},
                headers=headers,
            )
            assert resp.status_code == 200


class TestListReports:
    def test_list_reports(self, client, headers):
        with patch("kryon.server.routes.reports.list_reports", return_value=[]):
            resp = client.get("/api/v1/reports", headers=headers)
            assert resp.status_code == 200
            assert isinstance(resp.json(), list)
