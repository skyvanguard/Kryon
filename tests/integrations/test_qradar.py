"""Tests for QRadar LEEF forwarder."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.qradar import QRadarLEEFForwarder


def _make_config():
    return {
        "name": "test-qradar",
        "endpoint": "https://qradar.example.com/api/siem",
        "token": "qradar-token",
        "config_json": {},
    }


def _make_event(**kwargs):
    defaults = {"event_type": "finding", "severity": "high", "title": "XSS Detected", "description": "Found XSS"}
    defaults.update(kwargs)
    return SIEMEvent(**defaults)


class TestQRadarLEEFForwarder:
    def test_to_leef_format(self):
        fwd = QRadarLEEFForwarder(_make_config())
        event = _make_event()
        leef = fwd.to_leef(event)
        assert leef.startswith("LEEF:2.0|Kryon|KRYON|2.1.0|")
        assert "severity=8" in leef
        assert "title=XSS Detected" in leef

    def test_to_leef_with_client_and_user(self):
        fwd = QRadarLEEFForwarder(_make_config())
        event = _make_event(client_id="client-123", user="admin")
        leef = fwd.to_leef(event)
        assert "clientId=client-123" in leef
        assert "user=admin" in leef

    @pytest.mark.asyncio
    async def test_send_event_success(self):
        fwd = QRadarLEEFForwarder(_make_config())
        mock_resp = MagicMock(status_code=200, text="OK")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client
            result = await fwd.send_event(_make_event())
            assert result is True

    @pytest.mark.asyncio
    async def test_send_event_failure(self):
        fwd = QRadarLEEFForwarder(_make_config())
        mock_resp = MagicMock(status_code=500, text="Error")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client
            result = await fwd.send_event(_make_event())
            assert result is False

    def test_should_forward_default(self):
        fwd = QRadarLEEFForwarder(_make_config())
        assert fwd.should_forward(_make_event()) is True

    def test_leef_severity_mapping(self):
        fwd = QRadarLEEFForwarder(_make_config())
        for sev, expected in [("critical", 10), ("high", 8), ("medium", 5), ("low", 3), ("info", 1)]:
            leef = fwd.to_leef(_make_event(severity=sev))
            assert f"severity={expected}" in leef
