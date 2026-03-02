"""Tests for discovery.cloud_posture — cloud security posture aggregation."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.discovery.cloud_posture import aggregate_cloud_posture


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# aggregate_cloud_posture
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregate_all(monkeypatch):
    """Default (all) providers triggers Prowler AWS scan."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Prowler findings: 42"

    monkeypatch.setattr("kryon.tools.discovery.cloud_posture.run_command", fake_run)

    result = await _invoke(aggregate_cloud_posture, {})
    assert "Cloud Security Posture Assessment" in result
    assert "Prowler" in result


@pytest.mark.asyncio
async def test_aggregate_aws(monkeypatch):
    """AWS provider triggers Prowler scan."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "prowler output"

    monkeypatch.setattr("kryon.tools.discovery.cloud_posture.run_command", fake_run)

    result = await _invoke(aggregate_cloud_posture, {"provider": "aws"})
    assert "Prowler" in result
    assert any("prowler aws" in c for c in calls)


@pytest.mark.asyncio
async def test_aggregate_with_prowler_output(monkeypatch):
    """Providing prowler_output path reads the file instead of running prowler."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Prowler findings: 10"

    monkeypatch.setattr("kryon.tools.discovery.cloud_posture.run_command", fake_run)

    result = await _invoke(
        aggregate_cloud_posture,
        {
            "prowler_output": "/tmp/prowler-results.json",
        },
    )
    assert "Prowler" in result
    assert "prowler-results.json" in captured["cmd"]


@pytest.mark.asyncio
async def test_aggregate_with_scoutsuite_output(monkeypatch):
    """Providing scoutsuite_output path reads the file."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "scoutsuite data"

    monkeypatch.setattr("kryon.tools.discovery.cloud_posture.run_command", fake_run)

    result = await _invoke(
        aggregate_cloud_posture,
        {
            "scoutsuite_output": "/tmp/scoutsuite-results.json",
        },
    )
    assert "ScoutSuite" in result
    assert any("scoutsuite-results.json" in c for c in calls)
