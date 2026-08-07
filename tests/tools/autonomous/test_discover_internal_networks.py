"""Tests for _discover_internal_networks rewrite.

The function was dead: every one of its 7 methods called a non-existent tool
function (netstat.get_routing_table, netcat.execute_command, ...), so the broad
``except: pass`` swallowed the AttributeError and it ALWAYS returned []. The
rewrite:
  - wires the real SSH executor (injectable ``run_cmd``);
  - fixes the RFC1918 bug (old prefix "172." treated all of 172.0.0.0/8 as
    private; only 172.16.0.0/12 is) via ipaddress.is_private;
  - isolates each command (one failure no longer aborts discovery + fallback);
  - de-duplicates and always runs the /24 fallback.
"""

from __future__ import annotations

from kryon.tools.autonomous.orchestrator import (
    _as_private_network,
    _discover_internal_networks,
    _networks_from_text,
    _private_24_from_ip,
)

# --- _as_private_network ----------------------------------------------------


def test_as_private_network_keeps_rfc1918():
    assert _as_private_network("10.0.0.0/24") == "10.0.0.0/24"
    assert _as_private_network("192.168.1.0/24") == "192.168.1.0/24"
    assert _as_private_network("172.16.0.0/12") == "172.16.0.0/12"
    assert _as_private_network("172.31.9.0/24") == "172.31.9.0/24"


def test_as_private_network_excludes_public_172_bug():
    # The old string-prefix "172." wrongly matched these public ranges.
    assert _as_private_network("172.15.0.0/24") is None
    assert _as_private_network("172.32.0.0/24") is None
    assert _as_private_network("172.200.1.0/24") is None


def test_as_private_network_excludes_public_and_junk():
    assert _as_private_network("8.8.8.0/24") is None
    assert _as_private_network("garbage") is None
    assert _as_private_network("") is None


# --- _private_24_from_ip ----------------------------------------------------


def test_private_24_from_ip():
    assert _private_24_from_ip("10.1.2.3") == "10.1.2.0/24"
    assert _private_24_from_ip("172.16.5.9") == "172.16.5.0/24"
    assert _private_24_from_ip("192.168.1.55") == "192.168.1.0/24"


def test_private_24_from_ip_excludes_public():
    assert _private_24_from_ip("172.15.5.9") is None  # 172. bug
    assert _private_24_from_ip("172.40.1.1") is None
    assert _private_24_from_ip("8.8.8.8") is None
    assert _private_24_from_ip("notanip") is None


# --- _networks_from_text ----------------------------------------------------


def test_networks_from_text_mix_and_dedup():
    text = "10.0.0.0/24\n10.0.0.5\n172.16.1.9\n8.8.8.8\n"
    # 10.0.0.0/24 (cidr) — 10.0.0.5 collapses to the same /24 (deduped) —
    # 172.16.1.9 → its /24 — 8.8.8.8 public excluded.
    assert _networks_from_text(text) == ["10.0.0.0/24", "172.16.1.0/24"]


def test_networks_from_text_empty():
    assert _networks_from_text("") == []
    assert _networks_from_text("no ips here") == []


# --- _discover_internal_networks (injected runner) --------------------------


def test_discover_happy_path_private_only():
    blob = (
        "default via 10.0.0.1 dev eth0\n"
        "10.0.0.0/24 dev eth0 proto kernel\n"
        "172.16.5.0/24 dev eth1\n"
        "172.15.9.0/24 dev eth2\n"  # PUBLIC (172.15) — must be excluded
        "8.8.8.0/24 via 1.2.3.4\n"  # public
        "192.168.50.7\n"  # bare private IP → /24
    )
    nets = _discover_internal_networks("10.0.0.9", {}, run_cmd=lambda c: blob)

    assert "10.0.0.0/24" in nets
    assert "172.16.5.0/24" in nets
    assert "192.168.50.0/24" in nets
    assert "172.15.9.0/24" not in nets  # the RFC1918 bug fix
    assert "8.8.8.0/24" not in nets


def test_discover_fallback_to_pivot_24_when_empty():
    nets = _discover_internal_networks("10.0.5.20", {}, run_cmd=lambda c: "")
    assert nets == ["10.0.5.0/24"]


def test_discover_isolates_a_failing_command():
    def run(cmd: str) -> str:
        if "ip route" in cmd:
            raise RuntimeError("ssh dropped mid-command")
        if "/etc/hosts" in cmd:
            return "192.168.9.5 host1\n"
        return ""

    nets = _discover_internal_networks("10.0.0.9", {}, run_cmd=run)
    # the failing routes command didn't abort discovery — /etc/hosts still ran
    assert "192.168.9.0/24" in nets


def test_discover_uses_windows_command_set():
    seen: list[str] = []

    def run(cmd: str) -> str:
        seen.append(cmd)
        return "10.10.10.0/24\n"

    _discover_internal_networks("10.10.10.5", {"platform": "windows"}, run_cmd=run)

    assert any("route print" in c for c in seen)
    assert not any("ip route" in c for c in seen)


def test_discover_no_credentials_returns_fallback():
    # Default runner with no password/key → every command yields "" → fallback.
    nets = _discover_internal_networks("192.168.7.30", {})
    assert nets == ["192.168.7.0/24"]
