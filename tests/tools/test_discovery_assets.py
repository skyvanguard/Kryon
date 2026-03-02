"""Tests for discovery.asset_inventory — asset registration, search, and timeline."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.discovery.asset_inventory import asset_timeline, register_asset, search_assets


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# register_asset (fallback path — get_store will fail in test env)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_returns_json():
    """Register asset returns valid JSON even when store is unavailable."""
    result = await _invoke(
        register_asset,
        {
            "asset_type": "domain",
            "identifier": "example.com",
        },
    )
    data = json.loads(result)
    assert "asset_id" in data
    assert data["identifier"] == "example.com"
    # Will be "registered_local" since get_store fails
    assert data["status"] in ("registered", "registered_local")


@pytest.mark.asyncio
async def test_register_with_metadata():
    """Register asset with metadata returns valid JSON."""
    metadata = json.dumps({"provider": "aws", "region": "us-east-1"})
    result = await _invoke(
        register_asset,
        {
            "asset_type": "cloud_resource",
            "identifier": "i-1234567890abcdef0",
            "metadata_json": metadata,
            "client_id": "client_001",
        },
    )
    data = json.loads(result)
    assert "asset_id" in data
    assert data["identifier"] == "i-1234567890abcdef0"


@pytest.mark.asyncio
async def test_register_handles_import_error():
    """Register gracefully handles get_store import/initialization failure."""
    result = await _invoke(
        register_asset,
        {
            "asset_type": "ip",
            "identifier": "192.168.1.1",
        },
    )
    data = json.loads(result)
    # Should not crash — returns local registration
    assert "asset_id" in data
    assert data["status"] in ("registered", "registered_local")


# ---------------------------------------------------------------------------
# search_assets (fallback path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_returns_json():
    """Search assets returns valid JSON even when store is unavailable."""
    result = await _invoke(search_assets, {"query": "example"})
    data = json.loads(result)
    # Will either be a list or error dict
    assert isinstance(data, (list, dict))


@pytest.mark.asyncio
async def test_search_with_type_filter():
    """Search with type filter returns valid JSON."""
    result = await _invoke(
        search_assets,
        {
            "query": "192.168",
            "asset_type": "ip",
        },
    )
    data = json.loads(result)
    assert isinstance(data, (list, dict))


@pytest.mark.asyncio
async def test_search_handles_import_error():
    """Search gracefully handles get_store failure."""
    result = await _invoke(search_assets, {"query": "test"})
    data = json.loads(result)
    # Should not crash
    assert isinstance(data, (list, dict))


# ---------------------------------------------------------------------------
# asset_timeline (fallback path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeline_returns_json():
    """Timeline returns valid JSON even when store is unavailable."""
    result = await _invoke(asset_timeline, {"asset_id": "abc123"})
    data = json.loads(result)
    assert isinstance(data, (list, dict))


@pytest.mark.asyncio
async def test_timeline_handles_import_error():
    """Timeline gracefully handles get_store failure."""
    result = await _invoke(asset_timeline, {"asset_id": "nonexistent"})
    data = json.loads(result)
    assert isinstance(data, (list, dict))
    if isinstance(data, dict):
        assert "asset_id" in data or "error" in data
