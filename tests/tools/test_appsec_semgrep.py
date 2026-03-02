"""Tests for appsec.semgrep — Semgrep SAST wrapper tools."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.appsec.semgrep import semgrep_scan, semgrep_scan_with_rules


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# semgrep_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_semgrep_scan_default(monkeypatch):
    """Default scan uses config=auto and default severity."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Found 3 issues"

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(semgrep_scan, {"target_path": "/app/src"})
    assert "Found 3 issues" in result
    assert "--config auto" in captured["cmd"]
    assert "--severity ERROR,WARNING" in captured["cmd"]
    assert "/app/src" in captured["cmd"]


@pytest.mark.asyncio
async def test_semgrep_scan_custom_config(monkeypatch):
    """Custom config parameter is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(semgrep_scan, {"target_path": "/src", "config": "p/owasp-top-ten"})
    assert "--config p/owasp-top-ten" in captured["cmd"]


@pytest.mark.asyncio
async def test_semgrep_scan_json_output(monkeypatch):
    """JSON output format adds --json flag."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"results": []}'

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(semgrep_scan, {"target_path": "/src", "output_format": "json"})
    assert "--json" in captured["cmd"]


@pytest.mark.asyncio
async def test_semgrep_scan_language_filter(monkeypatch):
    """Language filter adds --lang flag."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(semgrep_scan, {"target_path": "/src", "language": "python"})
    assert "--lang python" in captured["cmd"]


@pytest.mark.asyncio
async def test_semgrep_scan_exclude_patterns(monkeypatch):
    """Exclude patterns are forwarded as --exclude flags."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "OK"

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(semgrep_scan, {"target_path": "/src", "exclude": "tests,vendor"})
    assert "--exclude" in captured["cmd"]
    assert "tests" in captured["cmd"]
    assert "vendor" in captured["cmd"]


# ---------------------------------------------------------------------------
# semgrep_scan_with_rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_semgrep_scan_with_rules_default(monkeypatch):
    """Default scan_with_rules uses JSON output."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"findings": []}'

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(
        semgrep_scan_with_rules,
        {
            "target_path": "/app",
            "rule_file": "/rules/custom.yml",
        },
    )
    assert "--config /rules/custom.yml" in captured["cmd"]
    assert "--json" in captured["cmd"]
    assert "/app" in captured["cmd"]


@pytest.mark.asyncio
async def test_semgrep_scan_with_rules_sarif(monkeypatch):
    """SARIF output format adds --sarif flag."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "sarif output"

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(
        semgrep_scan_with_rules,
        {
            "target_path": "/app",
            "rule_file": "/rules/xss.yml",
            "output_format": "sarif",
        },
    )
    assert "--sarif" in captured["cmd"]


@pytest.mark.asyncio
async def test_semgrep_scan_with_rules_text(monkeypatch):
    """Text output format does not add --json or --sarif."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "text output"

    monkeypatch.setattr("kryon.tools.appsec.semgrep.run_command", fake_run)

    result = await _invoke(
        semgrep_scan_with_rules,
        {
            "target_path": "/app",
            "rule_file": "/rules/custom.yml",
            "output_format": "text",
        },
    )
    assert "--json" not in captured["cmd"]
    assert "--sarif" not in captured["cmd"]
