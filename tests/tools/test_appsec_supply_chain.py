"""Tests for appsec.supply_chain — dependency confusion and typosquatting detection."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.appsec.supply_chain import detect_dependency_confusion, check_typosquatting


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# detect_dependency_confusion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_npm_confusion(monkeypatch):
    """NPM package.json triggers npm audit."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"advisories": {}}'

    monkeypatch.setattr("kryon.tools.appsec.supply_chain.run_command", fake_run)

    result = await _invoke(detect_dependency_confusion, {
        "package_manifest": "/app/package.json",
    })
    assert "NPM Audit" in result
    assert "npm audit" in captured["cmd"]


@pytest.mark.asyncio
async def test_pip_confusion(monkeypatch):
    """requirements.txt triggers pip-audit."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "No vulnerabilities found"

    monkeypatch.setattr("kryon.tools.appsec.supply_chain.run_command", fake_run)

    result = await _invoke(detect_dependency_confusion, {
        "package_manifest": "/app/requirements.txt",
    })
    assert "Pip Audit" in result
    assert "pip-audit" in captured["cmd"]


@pytest.mark.asyncio
async def test_pom_confusion(monkeypatch):
    """pom.xml triggers mvn dependency:analyze."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "BUILD SUCCESS"

    monkeypatch.setattr("kryon.tools.appsec.supply_chain.run_command", fake_run)

    result = await _invoke(detect_dependency_confusion, {
        "package_manifest": "/app/pom.xml",
    })
    assert "Maven Analysis" in result
    assert "mvn dependency:analyze" in captured["cmd"]


@pytest.mark.asyncio
async def test_generic_confusion(monkeypatch):
    """Unknown manifest falls back to syft analysis."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.appsec.supply_chain.run_command", fake_run)

    result = await _invoke(detect_dependency_confusion, {
        "package_manifest": "/app/Gemfile.lock",
    })
    assert "Syft Analysis" in result
    assert "syft" in captured["cmd"]


# ---------------------------------------------------------------------------
# check_typosquatting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_typosquatting_npm(monkeypatch):
    """NPM typosquatting check runs npm search."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "[]"

    monkeypatch.setattr("kryon.tools.appsec.supply_chain.run_command", fake_run)

    result = await _invoke(check_typosquatting, {
        "package_name": "express",
        "ecosystem": "npm",
    })
    assert "express" in result
    assert "npm" in result.lower()
    assert "npm search" in captured["cmd"]


@pytest.mark.asyncio
async def test_typosquatting_pypi(monkeypatch):
    """PyPI typosquatting check runs pip index."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "requests (2.31.0)"

    monkeypatch.setattr("kryon.tools.appsec.supply_chain.run_command", fake_run)

    result = await _invoke(check_typosquatting, {
        "package_name": "requests",
        "ecosystem": "pypi",
    })
    assert "requests" in result
    assert "pip index" in captured["cmd"]
