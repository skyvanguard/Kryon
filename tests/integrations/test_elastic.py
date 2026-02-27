"""Tests for Elastic SIEM forwarder."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.elastic import ElasticSIEMForwarder


def _make_config():
    return {
        "name": "test-elastic",
        "endpoint": "https://elastic.example.com:9200",
        "token": "elastic-api-key",
        "index_name": "kryon-events",
        "config_json": {},
    }


def _make_event(**kwargs):
    defaults = {"event_type": "finding", "severity": "critical", "title": "RCE Found", "description": "Remote code execution"}
    defaults.update(kwargs)
    return SIEMEvent(**defaults)


class TestElasticSIEMForwarder:
    def test_to_ecs_format(self):
        fwd = ElasticSIEMForwarder(_make_config())
        event = _make_event()
        ecs = fwd.to_ecs(event)
        assert "@timestamp" in ecs
        assert ecs["event"]["kind"] == "alert"
        assert ecs["event"]["category"] == ["threat"]
        assert ecs["observer"]["name"] == "kryon"
        assert ecs["message"] == "RCE Found"

    def test_to_ecs_non_finding(self):
        fwd = ElasticSIEMForwarder(_make_config())
        event = _make_event(event_type="scan_start")
        ecs = fwd.to_ecs(event)
        assert ecs["event"]["kind"] == "event"

    @pytest.mark.asyncio
    async def test_send_event_success(self):
        fwd = ElasticSIEMForwarder(_make_config())
        mock_resp = MagicMock(status_code=201, text='{"result":"created"}')
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
        fwd = ElasticSIEMForwarder(_make_config())
        mock_resp = MagicMock(status_code=503, text="Unavailable")
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
        fwd = ElasticSIEMForwarder(_make_config())
        mock_resp = MagicMock(status_code=200, text='{"errors":false}')
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client
            events = [_make_event(title=f"Finding {i}") for i in range(5)]
            count = await fwd.send_batch(events)
            assert count == 5

    def test_should_forward_default(self):
        fwd = ElasticSIEMForwarder(_make_config())
        assert fwd.should_forward(_make_event()) is True
