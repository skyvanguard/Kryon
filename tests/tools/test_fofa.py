"""Tests for reconnaissance.fofa — FOFA cyberspace search engine client."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.reconnaissance.fofa import fofa_host_detail, fofa_search


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# fofa_search
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_no_creds(monkeypatch):
    """Missing FOFA credentials returns error."""
    monkeypatch.delenv("FOFA_EMAIL", raising=False)
    monkeypatch.delenv("FOFA_KEY", raising=False)

    result = await _invoke(fofa_search, {"query": 'domain="example.com"'})
    assert "Error" in result
    assert "FOFA_EMAIL" in result


@pytest.mark.asyncio
async def test_search_with_creds(monkeypatch):
    """Valid credentials build correct curl command."""
    captured = {}
    monkeypatch.setenv("FOFA_EMAIL", "test@example.com")
    monkeypatch.setenv("FOFA_KEY", "testkey123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"results": []}'

    monkeypatch.setattr("kryon.tools.reconnaissance.fofa.run_command", fake_run)

    result = await _invoke(fofa_search, {"query": 'domain="example.com"'})
    assert "fofa.info/api/v1/search" in captured["cmd"]
    assert "test@example.com" in captured["cmd"]
    assert "testkey123" in captured["cmd"]
    # Query should be base64 encoded
    assert "qbase64=" in captured["cmd"]


@pytest.mark.asyncio
async def test_search_custom_fields(monkeypatch):
    """Custom fields are forwarded in the API call."""
    captured = {}
    monkeypatch.setenv("FOFA_EMAIL", "user@test.com")
    monkeypatch.setenv("FOFA_KEY", "key123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.reconnaissance.fofa.run_command", fake_run)

    result = await _invoke(
        fofa_search,
        {
            "query": 'port="443"',
            "fields": "host,ip,port,protocol",
        },
    )
    assert "fields=host,ip,port,protocol" in captured["cmd"]


@pytest.mark.asyncio
async def test_search_custom_size(monkeypatch):
    """Custom size parameter is forwarded."""
    captured = {}
    monkeypatch.setenv("FOFA_EMAIL", "user@test.com")
    monkeypatch.setenv("FOFA_KEY", "key123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.reconnaissance.fofa.run_command", fake_run)

    result = await _invoke(
        fofa_search,
        {
            "query": 'app="Apache"',
            "size": 500,
        },
    )
    assert "size=500" in captured["cmd"]


# ---------------------------------------------------------------------------
# fofa_host_detail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_detail_no_creds(monkeypatch):
    """Missing FOFA credentials returns error."""
    monkeypatch.delenv("FOFA_EMAIL", raising=False)
    monkeypatch.delenv("FOFA_KEY", raising=False)

    result = await _invoke(fofa_host_detail, {"host": "1.2.3.4"})
    assert "Error" in result


@pytest.mark.asyncio
async def test_host_detail_with_creds(monkeypatch):
    """Valid credentials build correct host detail URL."""
    captured = {}
    monkeypatch.setenv("FOFA_EMAIL", "test@example.com")
    monkeypatch.setenv("FOFA_KEY", "testkey123")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"host": "1.2.3.4", "ports": [80, 443]}'

    monkeypatch.setattr("kryon.tools.reconnaissance.fofa.run_command", fake_run)

    result = await _invoke(fofa_host_detail, {"host": "1.2.3.4"})
    assert "/api/v1/host/1.2.3.4" in captured["cmd"]
    assert "detail=true" in captured["cmd"]
