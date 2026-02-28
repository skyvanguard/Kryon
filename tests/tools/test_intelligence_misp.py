"""Tests for intelligence.misp_client — MISP threat intelligence platform client."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.intelligence.misp_client import misp_search_events, misp_add_event


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# misp_search_events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_no_creds(monkeypatch):
    """Missing MISP credentials returns error."""
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)

    result = await _invoke(misp_search_events, {"query": "malware"})
    assert "Error" in result
    assert "MISP_URL" in result


@pytest.mark.asyncio
async def test_search_with_creds(monkeypatch):
    """Valid MISP credentials build correct curl command."""
    captured = {}
    monkeypatch.setenv("MISP_URL", "https://misp.local")
    monkeypatch.setenv("MISP_KEY", "misp_api_key_123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"response": []}'

    monkeypatch.setattr("kryon.tools.intelligence.misp_client.run_command", fake_run)

    result = await _invoke(misp_search_events, {"query": "malware"})
    assert "misp.local/events/restSearch" in captured["cmd"]
    assert "misp_api_key_123" in captured["cmd"]


@pytest.mark.asyncio
async def test_search_with_type_filter(monkeypatch):
    """Type attribute filter is forwarded in request body."""
    captured = {}
    monkeypatch.setenv("MISP_URL", "https://misp.local")
    monkeypatch.setenv("MISP_KEY", "key123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"response": []}'

    monkeypatch.setattr("kryon.tools.intelligence.misp_client.run_command", fake_run)

    result = await _invoke(misp_search_events, {
        "query": "10.0.0.1",
        "type_attribute": "ip-src",
    })
    assert "ip-src" in captured["cmd"]


# ---------------------------------------------------------------------------
# misp_add_event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_event_no_creds(monkeypatch):
    """Missing MISP credentials returns error."""
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)

    result = await _invoke(misp_add_event, {
        "title": "Test Event",
        "description": "Test description",
    })
    assert "Error" in result
    assert "MISP_URL" in result


@pytest.mark.asyncio
async def test_add_event_with_creds(monkeypatch):
    """Valid credentials create event via POST."""
    captured = {}
    monkeypatch.setenv("MISP_URL", "https://misp.local")
    monkeypatch.setenv("MISP_KEY", "key123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"Event": {"id": "42"}}'

    monkeypatch.setattr("kryon.tools.intelligence.misp_client.run_command", fake_run)

    result = await _invoke(misp_add_event, {
        "title": "Phishing Campaign",
        "description": "Detected phishing targeting finance team",
    })
    assert "misp.local/events/add" in captured["cmd"]
    assert "Phishing Campaign" in captured["cmd"]


@pytest.mark.asyncio
async def test_add_event_with_attributes(monkeypatch):
    """Attributes are included in the event body."""
    captured = {}
    monkeypatch.setenv("MISP_URL", "https://misp.local")
    monkeypatch.setenv("MISP_KEY", "key123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"Event": {"id": "43"}}'

    monkeypatch.setattr("kryon.tools.intelligence.misp_client.run_command", fake_run)

    attrs = [
        {"type": "ip-src", "value": "10.0.0.1", "category": "Network activity"},
        {"type": "domain", "value": "evil.com", "category": "Network activity"},
    ]
    result = await _invoke(misp_add_event, {
        "title": "IOC Event",
        "description": "New IOCs discovered",
        "attributes_json": json.dumps(attrs),
    })
    assert "10.0.0.1" in captured["cmd"]
    assert "evil.com" in captured["cmd"]
