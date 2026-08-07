"""Tests for intelligence.stix_taxii — STIX 2.1 indicator/bundle creation and TAXII."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.intelligence.stix_taxii import (
    create_stix_bundle,
    create_stix_indicator,
    taxii_poll_feed,
)


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# create_stix_indicator (pure function — no run_command)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_indicator_ipv4():
    """IPv4 indicator has correct STIX pattern."""
    result = await _invoke(
        create_stix_indicator,
        {
            "ioc_type": "ipv4-addr",
            "ioc_value": "10.0.0.1",
        },
    )
    data = json.loads(result)
    assert data["type"] == "indicator"
    assert data["spec_version"] == "2.1"
    assert "[ipv4-addr:value = '10.0.0.1']" in data["pattern"]
    assert data["pattern_type"] == "stix"


@pytest.mark.asyncio
async def test_indicator_domain():
    """Domain indicator has correct STIX pattern."""
    result = await _invoke(
        create_stix_indicator,
        {
            "ioc_type": "domain-name",
            "ioc_value": "evil.example.com",
        },
    )
    data = json.loads(result)
    assert "[domain-name:value = 'evil.example.com']" in data["pattern"]


@pytest.mark.asyncio
async def test_indicator_with_name():
    """Custom name overrides default."""
    result = await _invoke(
        create_stix_indicator,
        {
            "ioc_type": "ipv4-addr",
            "ioc_value": "192.168.1.1",
            "name": "C2 Server IP",
        },
    )
    data = json.loads(result)
    assert data["name"] == "C2 Server IP"


@pytest.mark.asyncio
async def test_indicator_tlp_red():
    """TLP:RED uses correct STIX marking definition."""
    result = await _invoke(
        create_stix_indicator,
        {
            "ioc_type": "ipv4-addr",
            "ioc_value": "10.0.0.1",
            "tlp": "TLP:RED",
        },
    )
    data = json.loads(result)
    # TLP:RED marking definition ID
    assert "5e57c739-391a-4eb3-b6be-7d15ca92d5ed" in data["object_marking_refs"][0]


# ---------------------------------------------------------------------------
# create_stix_bundle (pure function)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bundle_from_list():
    """Bundle wraps multiple indicators."""
    indicators = [
        {"type": "indicator", "id": "indicator--aaa", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
        {"type": "indicator", "id": "indicator--bbb", "pattern": "[domain-name:value = 'evil.com']"},
    ]
    result = await _invoke(
        create_stix_bundle,
        {
            "indicators_json": json.dumps(indicators),
            "include_relationships": False,
        },
    )
    data = json.loads(result)
    assert data["type"] == "bundle"
    assert len(data["objects"]) == 2


@pytest.mark.asyncio
async def test_bundle_with_relationships():
    """Bundle with relationships creates relationship objects."""
    indicators = [
        {"type": "indicator", "id": "indicator--aaa", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
        {"type": "indicator", "id": "indicator--bbb", "pattern": "[domain-name:value = 'evil.com']"},
    ]
    result = await _invoke(
        create_stix_bundle,
        {
            "indicators_json": json.dumps(indicators),
            "include_relationships": True,
        },
    )
    data = json.loads(result)
    assert data["type"] == "bundle"
    # 2 indicators + 1 relationship
    assert len(data["objects"]) == 3
    rel = [o for o in data["objects"] if o["type"] == "relationship"]
    assert len(rel) == 1
    assert rel[0]["relationship_type"] == "related-to"


# ---------------------------------------------------------------------------
# taxii_poll_feed (uses run_command)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_taxii_list_collections(monkeypatch):
    """Empty collection_id lists available collections."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"collections": []}'

    monkeypatch.setattr("kryon.tools.intelligence.stix_taxii.run_command", fake_run)

    result = await _invoke(
        taxii_poll_feed,
        {
            "server_url": "https://taxii.example.com",
        },
    )
    assert "collections" in captured["cmd"]
    assert "taxii+json" in captured["cmd"]


@pytest.mark.asyncio
async def test_taxii_poll_feed(monkeypatch):
    """Specific collection_id polls that collection."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"objects": []}'

    monkeypatch.setattr("kryon.tools.intelligence.stix_taxii.run_command", fake_run)

    result = await _invoke(
        taxii_poll_feed,
        {
            "server_url": "https://taxii.example.com",
            "collection_id": "coll-123",
            "api_root": "api1",
        },
    )
    assert "coll-123/objects" in captured["cmd"]
    assert "api1" in captured["cmd"]
