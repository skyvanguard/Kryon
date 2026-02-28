"""Tests for intelligence.ioc_manager — IOC storage, search, and enrichment."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.intelligence.ioc_manager import store_ioc, search_iocs, enrich_ioc


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# store_ioc (fallback path — get_store will fail in test env)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_returns_json():
    """store_ioc returns valid JSON even when store is unavailable."""
    result = await _invoke(store_ioc, {
        "ioc_type": "ip",
        "ioc_value": "10.0.0.1",
        "source": "threat_feed",
    })
    data = json.loads(result)
    assert "ioc_id" in data
    assert data["type"] == "ip"
    assert data["value"] == "10.0.0.1"
    assert data["status"] in ("stored", "stored_local")


@pytest.mark.asyncio
async def test_store_handles_error():
    """store_ioc gracefully handles get_store failure."""
    result = await _invoke(store_ioc, {
        "ioc_type": "domain",
        "ioc_value": "evil.example.com",
    })
    data = json.loads(result)
    assert "ioc_id" in data
    assert data["status"] in ("stored", "stored_local")


# ---------------------------------------------------------------------------
# search_iocs (fallback path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_returns_json():
    """search_iocs returns valid JSON even when store is unavailable."""
    result = await _invoke(search_iocs, {"query": "10.0.0"})
    data = json.loads(result)
    assert isinstance(data, (list, dict))


@pytest.mark.asyncio
async def test_search_handles_error():
    """search_iocs gracefully handles get_store failure."""
    result = await _invoke(search_iocs, {
        "ioc_type": "ip",
        "min_score": 0.8,
    })
    data = json.loads(result)
    assert isinstance(data, (list, dict))


# ---------------------------------------------------------------------------
# enrich_ioc (uses run_command)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_all_sources(monkeypatch):
    """Enrichment with all sources queries multiple APIs."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return '{"data": "enrichment result"}'

    monkeypatch.setattr("kryon.tools.intelligence.ioc_manager.run_command", fake_run)

    result = await _invoke(enrich_ioc, {
        "ioc_type": "ip",
        "ioc_value": "10.0.0.1",
    })
    assert "IOC Enrichment" in result
    assert "10.0.0.1" in result
    # Should query virustotal, shodan, abuseipdb, otx for IP type
    assert len(calls) == 4


@pytest.mark.asyncio
async def test_enrich_virustotal_only(monkeypatch):
    """VirusTotal-only enrichment queries VT API."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"data": {"reputation": -5}}'

    monkeypatch.setattr("kryon.tools.intelligence.ioc_manager.run_command", fake_run)

    result = await _invoke(enrich_ioc, {
        "ioc_type": "domain",
        "ioc_value": "evil.com",
        "sources": "virustotal",
    })
    assert "VirusTotal" in result
    assert "virustotal" in captured["cmd"]


@pytest.mark.asyncio
async def test_enrich_shodan_ip(monkeypatch):
    """Shodan enrichment runs shodan host command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Organization: Example Corp"

    monkeypatch.setattr("kryon.tools.intelligence.ioc_manager.run_command", fake_run)

    result = await _invoke(enrich_ioc, {
        "ioc_type": "ip",
        "ioc_value": "1.2.3.4",
        "sources": "shodan",
    })
    assert "Shodan" in result
    assert "shodan host" in captured["cmd"]


@pytest.mark.asyncio
async def test_enrich_otx(monkeypatch):
    """AlienVault OTX enrichment queries OTX API."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"pulse_info": {"count": 5}}'

    monkeypatch.setattr("kryon.tools.intelligence.ioc_manager.run_command", fake_run)

    result = await _invoke(enrich_ioc, {
        "ioc_type": "ip",
        "ioc_value": "10.0.0.1",
        "sources": "otx",
    })
    assert "OTX" in result
    assert "otx.alienvault.com" in captured["cmd"]
