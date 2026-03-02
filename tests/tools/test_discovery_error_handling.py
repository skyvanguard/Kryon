"""Tests for error handling in discovery and intelligence tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


async def _invoke_tool(tool, args_json: str):
    """Helper to invoke a FunctionTool with JSON args."""
    ctx = MagicMock()
    ctx.context = None
    return await tool.on_invoke_tool(ctx, args_json)


@pytest.mark.asyncio
async def test_asm_discovery_scan_error_handling():
    """ASM engine returns JSON with error field on failure."""
    from kryon.tools.discovery.asm_engine import asm_discovery_scan

    with patch("kryon.tools.discovery.asm_engine.run_command", side_effect=RuntimeError("subfinder crash")):
        result = await _invoke_tool(
            asm_discovery_scan,
            json.dumps({"domain": "example.com", "include_subdomains": True, "include_ports": False}),
        )

    data = json.loads(result)
    assert "error" in data
    assert data["status"] == "failed"
    assert data["scan_id"]  # Still has scan_id


@pytest.mark.asyncio
async def test_cloud_posture_error_handling():
    """Cloud posture returns JSON error on failure."""
    from kryon.tools.discovery.cloud_posture import aggregate_cloud_posture

    with patch("kryon.tools.discovery.cloud_posture.run_command", side_effect=RuntimeError("prowler crash")):
        result = await _invoke_tool(
            aggregate_cloud_posture, json.dumps({"provider": "aws", "prowler_output": "/tmp/test.json"})
        )

    data = json.loads(result)
    assert "error" in data
    assert data["status"] == "failed"


@pytest.mark.asyncio
async def test_ioc_store_graceful_fallback():
    """IOC manager returns stored_local on DB failure."""
    from kryon.tools.intelligence.ioc_manager import store_ioc

    with patch("kryon.server.deps.get_store", side_effect=RuntimeError("no DB")):
        result = await _invoke_tool(store_ioc, json.dumps({"ioc_type": "ip", "ioc_value": "1.2.3.4", "source": "test"}))

    data = json.loads(result)
    assert data["status"] == "stored_local"
    assert "note" in data


@pytest.mark.asyncio
async def test_misp_search_missing_env(monkeypatch):
    """MISP client returns JSON error when env vars missing."""
    from kryon.tools.intelligence.misp_client import misp_search_events

    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)

    result = await _invoke_tool(misp_search_events, json.dumps({"query": "test"}))
    data = json.loads(result)
    assert "error" in data
    assert data["status"] == "failed"


@pytest.mark.asyncio
async def test_taxii_poll_feed_error_handling():
    """TAXII client returns JSON error on failure."""
    from kryon.tools.intelligence.stix_taxii import taxii_poll_feed

    with patch("kryon.tools.intelligence.stix_taxii.run_command", side_effect=RuntimeError("network error")):
        result = await _invoke_tool(
            taxii_poll_feed,
            json.dumps(
                {
                    "server_url": "https://taxii.example.com",
                    "collection_id": "col1",
                }
            ),
        )

    data = json.loads(result)
    assert "error" in data
    assert data["status"] == "failed"
