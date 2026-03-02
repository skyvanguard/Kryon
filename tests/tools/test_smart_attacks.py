"""Tests for password_cracking.smart_attacks — lockout-aware brute force and spraying."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.password_cracking.smart_attacks import credential_spray, smart_password_attack


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# smart_password_attack
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_attack(monkeypatch):
    """SSH attack builds hydra command with ssh module."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "[22][ssh] host: 10.0.0.1 login: admin password: admin123"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        smart_password_attack,
        {
            "target": "10.0.0.1",
            "service": "ssh",
        },
    )
    assert "hydra" in captured["cmd"]
    assert "ssh" in captured["cmd"]
    assert "Smart Password Attack" in result


@pytest.mark.asyncio
async def test_ftp_attack(monkeypatch):
    """FTP attack uses ftp module."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "no results"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        smart_password_attack,
        {
            "target": "10.0.0.1",
            "service": "ftp",
        },
    )
    assert "ftp" in captured["cmd"]


@pytest.mark.asyncio
async def test_unknown_service(monkeypatch):
    """Unknown service returns error."""
    result = await _invoke(
        smart_password_attack,
        {
            "target": "10.0.0.1",
            "service": "telnet_custom",
        },
    )
    assert "Error" in result
    assert "Unknown service" in result


@pytest.mark.asyncio
async def test_attack_with_lockout_params(monkeypatch):
    """Lockout parameters are reflected in output."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "no results"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        smart_password_attack,
        {
            "target": "10.0.0.1",
            "service": "ssh",
            "lockout_threshold": 3,
            "lockout_window_minutes": 15,
        },
    )
    assert "Lockout threshold: 3" in result
    assert "15min" in result
    # safe_attempts = max(1, 3-2) = 1
    assert "Safe attempts per account: 1" in result


@pytest.mark.asyncio
async def test_attack_dictionary_strategy(monkeypatch):
    """Dictionary strategy uses username and password lists."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "no results"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        smart_password_attack,
        {
            "target": "10.0.0.1",
            "service": "ssh",
            "strategy": "dictionary",
        },
    )
    assert "-L" in captured["cmd"]
    assert "-P" in captured["cmd"]
    assert "Strategy: dictionary" in result


@pytest.mark.asyncio
async def test_attack_spray_strategy(monkeypatch):
    """Spray strategy uses single password."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "no results"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        smart_password_attack,
        {
            "target": "10.0.0.1",
            "service": "ssh",
            "strategy": "spray",
        },
    )
    assert "-p" in captured["cmd"]
    assert "Password123!" in captured["cmd"]
    assert "Strategy: spray" in result


# ---------------------------------------------------------------------------
# credential_spray
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spray_multi_target(monkeypatch):
    """Multi-target spray runs hydra for each target."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "no results"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        credential_spray,
        {
            "targets": "10.0.0.1,10.0.0.2,10.0.0.3",
            "service": "ssh",
            "password": "Winter2024!",
        },
    )
    assert len(calls) == 3
    assert "Credential Spray: 3 targets" in result
    assert "[10.0.0.1]" in result
    assert "[10.0.0.2]" in result


@pytest.mark.asyncio
async def test_spray_custom_delay(monkeypatch):
    """Custom delay is forwarded to hydra."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "no results"

    monkeypatch.setattr("kryon.tools.password_cracking.smart_attacks.run_command", fake_run)

    result = await _invoke(
        credential_spray,
        {
            "targets": "10.0.0.1",
            "service": "ssh",
            "password": "test",
            "delay_seconds": 5.0,
        },
    )
    assert "-W 5.0" in captured["cmd"]
    assert "Delay: 5.0s" in result
