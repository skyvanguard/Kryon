"""Tests for appsec.zap — OWASP ZAP DAST wrapper tools."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.appsec.zap import zap_api_scan, zap_baseline_scan, zap_full_scan


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# zap_baseline_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_baseline_default(monkeypatch):
    """Baseline scan with default params uses zap-baseline.py."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "PASS: 0 alerts"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(zap_baseline_scan, {"target_url": "https://example.com"})
    assert "zap-baseline.py" in captured["cmd"]
    assert "-t https://example.com" in captured["cmd"]
    assert "-m 5" in captured["cmd"]
    assert "-J zap-report.json" in captured["cmd"]


@pytest.mark.asyncio
async def test_baseline_with_ajax(monkeypatch):
    """Ajax spider flag is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(
        zap_baseline_scan,
        {
            "target_url": "https://spa.example.com",
            "ajax_spider": True,
        },
    )
    assert "-j" in captured["cmd"]


@pytest.mark.asyncio
async def test_baseline_html_output(monkeypatch):
    """HTML output format adds -r flag."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(
        zap_baseline_scan,
        {
            "target_url": "https://example.com",
            "output_format": "html",
        },
    )
    assert "-r zap-report.html" in captured["cmd"]


# ---------------------------------------------------------------------------
# zap_full_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_scan_default(monkeypatch):
    """Full scan with default params includes ajax spider."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Full scan complete"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(zap_full_scan, {"target_url": "https://target.com"})
    assert "zap-full-scan.py" in captured["cmd"]
    assert "-j" in captured["cmd"]
    assert "-m 60" in captured["cmd"]


@pytest.mark.asyncio
async def test_full_scan_with_auth(monkeypatch):
    """Auth header is forwarded in the replacer config."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(
        zap_full_scan,
        {
            "target_url": "https://target.com",
            "auth_header": "Bearer tok123",
        },
    )
    assert "Bearer tok123" in captured["cmd"]
    assert "Authorization" in captured["cmd"]


# ---------------------------------------------------------------------------
# zap_api_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_scan_openapi(monkeypatch):
    """API scan with openapi format."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "API scan done"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(
        zap_api_scan,
        {
            "openapi_url": "https://api.example.com/openapi.json",
        },
    )
    assert "zap-api-scan.py" in captured["cmd"]
    assert "-f openapi" in captured["cmd"]
    assert "-t https://api.example.com/openapi.json" in captured["cmd"]


@pytest.mark.asyncio
async def test_api_scan_target_override(monkeypatch):
    """Target URL override uses -O flag."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(
        zap_api_scan,
        {
            "openapi_url": "https://docs.example.com/spec.json",
            "target_url": "https://staging.example.com",
        },
    )
    assert "-O https://staging.example.com" in captured["cmd"]


@pytest.mark.asyncio
async def test_api_scan_soap_format(monkeypatch):
    """SOAP format is forwarded to -f flag."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.zap.run_command", fake_run)

    result = await _invoke(
        zap_api_scan,
        {
            "openapi_url": "https://api.example.com/service?wsdl",
            "format": "soap",
        },
    )
    assert "-f soap" in captured["cmd"]
