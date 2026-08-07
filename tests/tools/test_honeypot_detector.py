"""Tests for reconnaissance.honeypot_detector — honeypot detection tools."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.reconnaissance.honeypot_detector import detect_honeypot, honeypot_score


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# detect_honeypot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_all_checks(monkeypatch):
    """All checks runs banner, timing, behavior, and fingerprint."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "scan output"

    monkeypatch.setattr("kryon.tools.reconnaissance.honeypot_detector.run_command", fake_run)

    result = await _invoke(detect_honeypot, {"target": "10.0.0.1"})
    assert "Honeypot Detection Analysis" in result
    assert "Banner Analysis" in result
    assert "Timing Analysis" in result
    assert "Fingerprint Check" in result
    assert "Behavior Analysis" in result
    assert len(calls) >= 4


@pytest.mark.asyncio
async def test_detect_banner_only(monkeypatch):
    """Banner-only check runs nmap service version scan."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "22/tcp open ssh OpenSSH"

    monkeypatch.setattr("kryon.tools.reconnaissance.honeypot_detector.run_command", fake_run)

    result = await _invoke(detect_honeypot, {"target": "10.0.0.1", "checks": "banner"})
    assert "Banner Analysis" in result
    assert "nmap" in captured["cmd"]
    assert "-sV" in captured["cmd"]
    # Should NOT contain other check sections
    assert "Timing Analysis" not in result


@pytest.mark.asyncio
async def test_detect_fingerprint_only(monkeypatch):
    """Fingerprint-only check runs nmap http-headers script."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "HTTP headers output"

    monkeypatch.setattr("kryon.tools.reconnaissance.honeypot_detector.run_command", fake_run)

    result = await _invoke(detect_honeypot, {"target": "10.0.0.1", "checks": "fingerprint"})
    assert "Fingerprint Check" in result
    assert "Cowrie" in result  # honeypot indicator list


@pytest.mark.asyncio
async def test_detect_timing_only(monkeypatch):
    """Timing-only check runs curl timing analysis."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "0.123\n0.125\n0.124"

    monkeypatch.setattr("kryon.tools.reconnaissance.honeypot_detector.run_command", fake_run)

    result = await _invoke(detect_honeypot, {"target": "10.0.0.1", "checks": "timing"})
    assert "Timing Analysis" in result
    assert "curl" in captured["cmd"]


# ---------------------------------------------------------------------------
# honeypot_score
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_honeypot_score_high(monkeypatch):
    """High score (>0.7) returns HIGH probability assessment."""

    def fake_run(cmd, **kwargs):
        return "0.85"

    monkeypatch.setattr("kryon.tools.reconnaissance.honeypot_detector.run_command", fake_run)

    result = await _invoke(honeypot_score, {"target": "10.0.0.1"})
    assert "HIGH" in result
    assert "0.85" in result


@pytest.mark.asyncio
async def test_honeypot_score_low(monkeypatch):
    """Low score (<0.4) returns LOW probability assessment."""

    def fake_run(cmd, **kwargs):
        return "0.15"

    monkeypatch.setattr("kryon.tools.reconnaissance.honeypot_detector.run_command", fake_run)

    result = await _invoke(honeypot_score, {"target": "10.0.0.1"})
    assert "LOW" in result
    assert "0.15" in result
