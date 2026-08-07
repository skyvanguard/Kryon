"""Tests for the network-pivot stubs turned real:
_enumerate_through_pivot (proxied nmap scan) and
_autonomous_compromise_through_pivot (delegates to autonomous_ctf_solver).

The scanner / solver are injected — nothing scans or exploits.
"""

from __future__ import annotations

from kryon.tools.autonomous.orchestrator import (
    _autonomous_compromise_through_pivot,
    _enumerate_through_pivot,
    _parse_nmap_hosts,
)

_NMAP = """
Starting Nmap
Nmap scan report for 192.168.100.5
Host is up.
22/tcp   open  ssh
80/tcp   open  http
Nmap scan report for db.internal (192.168.100.6)
3306/tcp open  mysql
Nmap scan report for 192.168.100.7
Host is up.
"""


def test_parse_nmap_hosts():
    hosts = _parse_nmap_hosts(_NMAP)
    ips = {h["ip"] for h in hosts}
    # .5 and .6 have open ports; .7 has none → dropped
    assert ips == {"192.168.100.5", "192.168.100.6"}
    five = next(h for h in hosts if h["ip"] == "192.168.100.5")
    assert {p["port"] for p in five["ports"]} == {22, 80}


def test_enumerate_through_pivot_parses_scanner_output():
    hosts = _enumerate_through_pivot("192.168.100.0/24", "127.0.0.1:1080", scanner=lambda n, p: _NMAP)
    assert {h["ip"] for h in hosts} == {"192.168.100.5", "192.168.100.6"}


def test_enumerate_through_pivot_scanner_failure_returns_empty():
    def boom(network: str, proxy: str) -> str:
        raise RuntimeError("proxychains missing")

    assert _enumerate_through_pivot("192.168.100.0/24", "127.0.0.1:1080", scanner=boom) == []


def test_compromise_through_pivot_success():
    def solver(ip: str) -> dict:
        return {"success": True, "privilege_level": "root", "services_exploited": ["ssh"]}

    out = _autonomous_compromise_through_pivot("192.168.100.5", "127.0.0.1:1080", solver=solver)
    assert out["success"] is True
    assert out["access_level"] == "root"
    assert out["services_exploited"] == ["ssh"]


def test_compromise_through_pivot_failure_maps_cleanly():
    out = _autonomous_compromise_through_pivot(
        "192.168.100.5", "127.0.0.1:1080", solver=lambda ip: {"success": False, "privilege_level": "none"}
    )
    assert out["success"] is False
    assert out["access_level"] == "none"


def test_compromise_through_pivot_solver_exception():
    def boom(ip: str) -> dict:
        raise RuntimeError("solver crashed")

    out = _autonomous_compromise_through_pivot("192.168.100.5", "127.0.0.1:1080", solver=boom)
    assert out["success"] is False
    assert "error" in out
