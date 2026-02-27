"""Tests for Splunk HEC forwarder."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.splunk import SplunkHECForwarder


def _make_config():
    return {
        "name": "test-splunk",
        "endpoint": "https://splunk.example.com:8088",
        "token": "test-token-123",
        "index_name": "security",
        "config_json": {},
    }


def _make_event(**kwargs):
    defaults = {"event_type": "finding", "severity": "high", "title": "SQL Injection", "description": "Found SQLi"}
    defaults.update(kwargs)
    return SIEMEvent(**defaults)


class TestSplunkHECForwarder:
    @pytest.mark.asyncio
    async def test_send_event_success(self):
        fwd = SplunkHECForwarder(_make_config())
        mock_resp = MagicMock(status_code=200, text="Success")
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
        fwd = SplunkHECForwarder(_make_config())
        mock_resp = MagicMock(status_code=503, text="Service Unavailable")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client
            result = await fwd.send_event(_make_event())
            assert result is False

    @pytest.mark.asyncio
    async def test_send_batch_success(self):
        fwd = SplunkHECForwarder(_make_config())
        mock_resp = MagicMock(status_code=200, text="Success")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client
            events = [_make_event(title=f"Finding {i}") for i in range(3)]
            count = await fwd.send_batch(events)
            assert count == 3

    def test_format_event(self):
        fwd = SplunkHECForwarder(_make_config())
        event = _make_event()
        data = fwd.format_event(event)
        assert data["event_type"] == "finding"
        assert data["severity"] == "high"

    def test_should_forward_default(self):
        fwd = SplunkHECForwarder(_make_config())
        assert fwd.should_forward(_make_event()) is True

    def test_should_forward_min_severity_filter(self):
        config = _make_config()
        config["config_json"] = {"min_severity": "high"}
        fwd = SplunkHECForwarder(config)
        assert fwd.should_forward(_make_event(severity="critical")) is True
        assert fwd.should_forward(_make_event(severity="high")) is True
        assert fwd.should_forward(_make_event(severity="low")) is False
