"""Tests for appsec.api_security — OWASP API Top 10 checks."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.appsec.api_security import api_security_scan, owasp_api_top10_check


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# api_security_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_all_checks(monkeypatch):
    """Default scan runs nuclei with all checks."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"findings": []}'

    monkeypatch.setattr("kryon.tools.appsec.api_security.run_command", fake_run)

    result = await _invoke(api_security_scan, {"target_url": "https://api.example.com"})
    assert "nuclei" in captured["cmd"]
    assert "-target https://api.example.com" in captured["cmd"]
    assert "-jsonl" in captured["cmd"]
    # "all" checks should NOT add -tags
    assert "-tags" not in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_specific_checks(monkeypatch):
    """Specific checks add -tags with mapped values."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.appsec.api_security.run_command", fake_run)

    result = await _invoke(api_security_scan, {
        "target_url": "https://api.example.com",
        "checks": "auth,injection",
    })
    assert "-tags auth,injection" in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_with_auth(monkeypatch):
    """Auth token is forwarded as Authorization header."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.appsec.api_security.run_command", fake_run)

    result = await _invoke(api_security_scan, {
        "target_url": "https://api.example.com",
        "auth_token": "secrettoken",
    })
    assert "Bearer secrettoken" in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_with_openapi_spec(monkeypatch):
    """OpenAPI spec triggers an additional ZAP scan."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "scan result"

    monkeypatch.setattr("kryon.tools.appsec.api_security.run_command", fake_run)

    result = await _invoke(api_security_scan, {
        "target_url": "https://api.example.com",
        "openapi_spec": "https://api.example.com/openapi.json",
    })
    # Should have 2 calls: nuclei + zap
    assert len(calls) == 2
    assert "nuclei" in calls[0]
    assert "zap-api-scan.py" in calls[1]
    assert "ZAP API Scan" in result


# ---------------------------------------------------------------------------
# owasp_api_top10_check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_owasp_api_top10_default(monkeypatch):
    """OWASP API Top 10 check runs multiple nuclei scans."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "no findings"

    monkeypatch.setattr("kryon.tools.appsec.api_security.run_command", fake_run)

    result = await _invoke(owasp_api_top10_check, {"target_url": "https://api.example.com"})
    # Should run 5 checks: BOLA, Auth, Rate-Limit, SSRF, Misconfig
    assert len(calls) == 5
    assert "API1-BOLA" in result
    assert "API2-Auth" in result
    assert "API8-Misconfig" in result


@pytest.mark.asyncio
async def test_owasp_api_top10_threshold(monkeypatch):
    """Severity threshold parameter is accepted."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "check done"

    monkeypatch.setattr("kryon.tools.appsec.api_security.run_command", fake_run)

    result = await _invoke(owasp_api_top10_check, {
        "target_url": "https://api.example.com",
        "severity_threshold": "critical",
    })
    assert len(calls) == 5
