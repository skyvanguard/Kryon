"""Tests for validation.attack_simulator — MITRE ATT&CK simulation engine."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.validation.attack_simulator import list_attack_techniques, simulate_attack


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# simulate_attack
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_simulate_t1046(monkeypatch):
    """T1046 Network Service Discovery builds nmap command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "80/tcp open http"

    monkeypatch.setattr("kryon.tools.validation.attack_simulator.run_command", fake_run)

    result = await _invoke(
        simulate_attack,
        {
            "technique_id": "T1046",
            "target": "10.0.0.1",
        },
    )
    assert "T1046" in result
    assert "Network Service Discovery" in result
    assert "10.0.0.1" in result
    assert "nmap" in captured["cmd"]


@pytest.mark.asyncio
async def test_simulate_t1190(monkeypatch):
    """T1190 Exploit Public-Facing Application builds nuclei command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "critical findings"

    monkeypatch.setattr("kryon.tools.validation.attack_simulator.run_command", fake_run)

    result = await _invoke(
        simulate_attack,
        {
            "technique_id": "T1190",
            "target": "https://target.com",
        },
    )
    assert "T1190" in result
    assert "nuclei" in captured["cmd"]


@pytest.mark.asyncio
async def test_simulate_unknown_technique(monkeypatch):
    """Unknown technique ID returns error."""

    def fake_run(cmd, **kwargs):
        return "should not run"

    monkeypatch.setattr("kryon.tools.validation.attack_simulator.run_command", fake_run)

    result = await _invoke(
        simulate_attack,
        {
            "technique_id": "T9999",
            "target": "10.0.0.1",
        },
    )
    assert "Error" in result
    assert "Unknown technique" in result


@pytest.mark.asyncio
async def test_simulate_full_mode(monkeypatch):
    """Full mode is accepted and reflected in output."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "scan output"

    monkeypatch.setattr("kryon.tools.validation.attack_simulator.run_command", fake_run)

    result = await _invoke(
        simulate_attack,
        {
            "technique_id": "T1046",
            "target": "10.0.0.1",
            "mode": "full",
        },
    )
    assert "Mode: full" in result


@pytest.mark.asyncio
async def test_simulate_t1110(monkeypatch):
    """T1110 Brute Force simulation returns dry-run message."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Simulation: brute force test"

    monkeypatch.setattr("kryon.tools.validation.attack_simulator.run_command", fake_run)

    result = await _invoke(
        simulate_attack,
        {
            "technique_id": "T1110",
            "target": "10.0.0.1",
        },
    )
    assert "T1110" in result
    assert "Brute Force" in result


# ---------------------------------------------------------------------------
# list_attack_techniques
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_all_techniques(monkeypatch):
    """List all techniques returns JSON with all entries."""
    result = await _invoke(list_attack_techniques, {})
    data = json.loads(result)
    assert isinstance(data, list)
    assert len(data) > 0
    assert all("technique_id" in t for t in data)


@pytest.mark.asyncio
async def test_list_by_tactic(monkeypatch):
    """Filter by tactic returns only matching techniques."""
    result = await _invoke(list_attack_techniques, {"tactic": "Discovery"})
    data = json.loads(result)
    assert isinstance(data, list)
    assert all(t["tactic"] == "Discovery" for t in data)


@pytest.mark.asyncio
async def test_list_discovery_only(monkeypatch):
    """Discovery tactic includes T1046."""
    result = await _invoke(list_attack_techniques, {"tactic": "Discovery"})
    data = json.loads(result)
    technique_ids = [t["technique_id"] for t in data]
    assert "T1046" in technique_ids
