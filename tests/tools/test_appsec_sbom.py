"""Tests for appsec.sbom — Syft/Grype SBOM and vulnerability scanning tools."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.appsec.sbom import generate_sbom, scan_sbom_vulns, dependency_tree


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# generate_sbom
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sbom_cyclonedx(monkeypatch):
    """CycloneDX format is default."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"bomFormat": "CycloneDX"}'

    monkeypatch.setattr("kryon.tools.appsec.sbom.run_command", fake_run)

    result = await _invoke(generate_sbom, {"target": "/app"})
    assert "syft" in captured["cmd"]
    assert "dir:/app" in captured["cmd"]
    assert "-o cyclonedx-json" in captured["cmd"]


@pytest.mark.asyncio
async def test_sbom_spdx(monkeypatch):
    """SPDX format is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.appsec.sbom.run_command", fake_run)

    result = await _invoke(generate_sbom, {"target": "/app", "format": "spdx-json"})
    assert "-o spdx-json" in captured["cmd"]


@pytest.mark.asyncio
async def test_sbom_image(monkeypatch):
    """Image source type is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.appsec.sbom.run_command", fake_run)

    result = await _invoke(generate_sbom, {"target": "nginx:latest", "source_type": "image"})
    assert "image:nginx:latest" in captured["cmd"]


# ---------------------------------------------------------------------------
# scan_sbom_vulns
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grype_scan_default(monkeypatch):
    """Default grype scan uses critical severity."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"matches": []}'

    monkeypatch.setattr("kryon.tools.appsec.sbom.run_command", fake_run)

    result = await _invoke(scan_sbom_vulns, {"target": "/app"})
    assert "grype" in captured["cmd"]
    assert "--fail-on critical" in captured["cmd"]
    assert "-o json" in captured["cmd"]


@pytest.mark.asyncio
async def test_grype_only_fixed(monkeypatch):
    """only_fixed flag is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.appsec.sbom.run_command", fake_run)

    result = await _invoke(scan_sbom_vulns, {"target": "/app", "only_fixed": True})
    assert "--only-fixed" in captured["cmd"]


# ---------------------------------------------------------------------------
# dependency_tree
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dependency_tree_npm(monkeypatch):
    """NPM package manager builds correct command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "project@1.0.0"

    monkeypatch.setattr("kryon.tools.appsec.sbom.run_command", fake_run)

    result = await _invoke(dependency_tree, {"project_path": "/app", "package_manager": "npm"})
    assert "npm ls" in captured["cmd"]
    assert "--depth=3" in captured["cmd"]
