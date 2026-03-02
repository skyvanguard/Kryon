"""Tests for discovery.asm_engine — Attack Surface Management discovery and diffing."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.discovery.asm_engine import asm_diff, asm_discovery_scan


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# asm_discovery_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_with_subdomains(monkeypatch):
    """Scan with subdomains runs subfinder."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "subfinder" in cmd:
            return "sub1.example.com\nsub2.example.com"
        return "80/tcp open http"

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(asm_discovery_scan, {"domain": "example.com"})
    data = json.loads(result)
    assert data["domain"] == "example.com"
    assert "sub1.example.com" in data["subdomains"]
    assert "sub2.example.com" in data["subdomains"]
    assert any("subfinder" in c for c in calls)


@pytest.mark.asyncio
async def test_scan_without_subdomains(monkeypatch):
    """Scan without subdomains skips subfinder."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "80/tcp open"

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(
        asm_discovery_scan,
        {
            "domain": "example.com",
            "include_subdomains": False,
        },
    )
    data = json.loads(result)
    assert data["subdomains"] == []
    assert not any("subfinder" in c for c in calls)


@pytest.mark.asyncio
async def test_scan_without_ports(monkeypatch):
    """Scan without ports skips nmap."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return "sub.example.com"

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(
        asm_discovery_scan,
        {
            "domain": "example.com",
            "include_ports": False,
        },
    )
    data = json.loads(result)
    assert data["services"] == []
    assert not any("nmap" in c for c in calls)


@pytest.mark.asyncio
async def test_scan_with_ports(monkeypatch):
    """Scan with ports runs nmap on discovered subdomains."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "subfinder" in cmd:
            return "sub.example.com"
        return "80/tcp open"

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(asm_discovery_scan, {"domain": "example.com"})
    data = json.loads(result)
    assert len(data["services"]) > 0
    assert any("nmap" in c for c in calls)


@pytest.mark.asyncio
async def test_scan_result_has_scan_id(monkeypatch):
    """Scan result includes a unique scan_id."""

    def fake_run(cmd, **kwargs):
        return ""

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(
        asm_discovery_scan,
        {
            "domain": "example.com",
            "include_subdomains": False,
            "include_ports": False,
        },
    )
    data = json.loads(result)
    assert "scan_id" in data
    assert len(data["scan_id"]) == 12


@pytest.mark.asyncio
async def test_scan_result_has_timestamp(monkeypatch):
    """Scan result includes a timestamp."""

    def fake_run(cmd, **kwargs):
        return ""

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(
        asm_discovery_scan,
        {
            "domain": "example.com",
            "include_subdomains": False,
            "include_ports": False,
        },
    )
    data = json.loads(result)
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_scan_domain_only(monkeypatch):
    """When no subdomains found, port scan uses the domain itself."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "subfinder" in cmd:
            return ""  # no subdomains
        return "443/tcp open"

    monkeypatch.setattr("kryon.tools.discovery.asm_engine.run_command", fake_run)

    result = await _invoke(asm_discovery_scan, {"domain": "single.com"})
    data = json.loads(result)
    # Port scan should still run using the domain
    nmap_calls = [c for c in calls if "nmap" in c]
    assert len(nmap_calls) > 0
    assert any("single.com" in c for c in nmap_calls)


# ---------------------------------------------------------------------------
# asm_diff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diff_returns_info(monkeypatch):
    """Diff returns informational JSON about needing stored scan data."""
    result = await _invoke(
        asm_diff,
        {
            "scan_id_old": "abc123",
            "scan_id_new": "def456",
        },
    )
    data = json.loads(result)
    assert data["old_scan_id"] == "abc123"
    assert data["new_scan_id"] == "def456"
    assert "status" in data
