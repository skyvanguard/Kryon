"""Recon-only gate — port-scanners / exploit tools are refused under KRYON_RECON_ONLY,
while HTTP recon passes through. Closes the gap where an --active run fired
`nmap --top-ports 2000` despite an explicit "no port scan" instruction."""

from __future__ import annotations

import pytest

from kryon.validation.recon_guard import recon_only_reason, recon_only_reason_for_tool


@pytest.fixture
def recon_only(monkeypatch):
    monkeypatch.setenv("KRYON_RECON_ONLY", "1")


def test_disabled_by_default_allows_everything(monkeypatch):
    monkeypatch.delenv("KRYON_RECON_ONLY", raising=False)
    assert recon_only_reason("nmap -Pn -T4 --top-ports 2000 app.example.com") is None


def test_blocks_nmap(recon_only):
    reason = recon_only_reason("nmap -Pn -T4 --top-ports 2000 app.example.com 2>&1")
    assert reason is not None
    assert "nmap" in reason
    assert "recon-only" in reason.lower()


@pytest.mark.parametrize(
    "cmd",
    [
        "masscan -p1-65535 10.0.0.1",
        "rustscan -a target",
        "sqlmap -u https://t/?id=1 --dump",
        "hydra -l admin -P rockyou.txt ssh://t",
        "sudo nmap -sS target",
        "torsocks nmap -Pn target",
        "proxychains4 nmap target",
        "/usr/bin/nmap -Pn target",
        "echo hi; nmap target",
    ],
)
def test_blocks_scanners_and_exploit_tools(recon_only, cmd):
    assert recon_only_reason(cmd) is not None


@pytest.mark.parametrize(
    "cmd",
    [
        "curl -s https://app.example.com/api/",
        "ffuf -u https://t/FUZZ -w /wl -x socks5://127.0.0.1:9050",
        "whatweb https://t",
        "curl -X OPTIONS https://t/api/v1",
        "curl https://t/nmap-results.txt",  # 'nmap' only as a path substring
        "cat /tmp/nmap_notes.md",  # 'nmap' as filename substring, not a command
    ],
)
def test_allows_http_recon_and_substring_false_positives(recon_only, cmd):
    assert recon_only_reason(cmd) is None


# --- recon_only_reason_for_tool: block dedicated wrappers by NAME -------------
# The dedicated tools (nmap, sqlmap_scan, hydra, …) call the raw dispatcher, not
# the guarded run_command — so the string check never sees them. The chokepoint
# variant blocks them by their function-tool name.


def test_for_tool_disabled_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_RECON_ONLY", raising=False)
    assert recon_only_reason_for_tool("nmap", {"target": "10.0.0.1"}) is None


@pytest.mark.parametrize(
    "tool_name",
    ["nmap", "masscan", "rustscan", "sqlmap", "sqlmap_scan", "sqlmap_dump_database", "hydra", "medusa"],
)
def test_for_tool_blocks_dedicated_scanners(recon_only, tool_name):
    reason = recon_only_reason_for_tool(tool_name, {"target": "10.0.0.1", "args": "-p-"})
    assert reason is not None
    assert "recon-only" in reason.lower()


@pytest.mark.parametrize("tool_name", ["web_fetch_smart", "curl_request", "whatweb_scan", "dns_lookup"])
def test_for_tool_allows_http_recon_tools(recon_only, tool_name):
    assert recon_only_reason_for_tool(tool_name, {"url": "https://t/"}) is None


def test_for_tool_inspects_generic_runner_command(recon_only):
    # run_command carrying an nmap invocation is still caught via the string check.
    assert recon_only_reason_for_tool("run_command", {"command": "nmap -p- 10.0.0.1"}) is not None
    assert recon_only_reason_for_tool("run_command", {"command": "curl https://t/"}) is None
    # JSON-string arguments (as the SDK chokepoint passes them) are parsed too.
    assert recon_only_reason_for_tool("run_command", '{"command": "sqlmap -u https://t --dump"}') is not None
