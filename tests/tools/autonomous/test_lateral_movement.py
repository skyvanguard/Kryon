"""Tests for _check_lateral_movement rewrite.

The old function called 6+ non-existent tool functions under one broad except,
so it always returned []. The rewrite runs real commands over an injectable
``run_cmd`` (the pivot SSH executor) and parses their output; without a runner
it returns [] instead of pretending.
"""

from __future__ import annotations

from kryon.tools.autonomous.orchestrator import _check_lateral_movement

_SHELL = {"exploitation_path": [{"shell_obtained": True}]}


def test_no_shell_access_returns_empty():
    assert _check_lateral_movement("10.0.0.9", {"exploitation_path": []}, run_cmd=lambda c: "x") == []


def test_no_runner_returns_empty():
    # shell obtained but no executor threaded → honest [] (can't reach the host)
    assert _check_lateral_movement("10.0.0.9", _SHELL) == []


def test_parses_networks_keys_docker():
    def run(cmd: str) -> str:
        if "ip route" in cmd:
            return "10.0.0.0/24 dev eth0\n172.16.5.0/24 dev eth1\n8.8.8.0/24 dev eth2\n"
        if "find" in cmd:
            return "/root/.ssh/id_rsa\n/home/bob/.ssh/id_ed25519\n"
        if "docker ps" in cmd:
            return "web\ndb\n"
        return ""

    opps = _check_lateral_movement("10.0.0.9", _SHELL, run_cmd=run)
    by_type: dict[str, list] = {}
    for o in opps:
        by_type.setdefault(o["type"], []).append(o)

    nets = {o["target_network"] for o in by_type.get("routed_network", [])}
    assert "10.0.0.0/24" in nets
    assert "172.16.5.0/24" in nets
    assert "8.8.8.0/24" not in nets  # public excluded (RFC1918 correct)

    keys = {o["key_path"] for o in by_type.get("ssh_key_found", [])}
    assert keys == {"/root/.ssh/id_rsa", "/home/bob/.ssh/id_ed25519"}

    assert by_type["docker_access"][0]["containers"] == ["web", "db"]


def test_probe_failure_is_isolated():
    def run(cmd: str) -> str:
        if "ip route" in cmd:
            raise RuntimeError("ssh dropped")
        if "docker ps" in cmd:
            return "only_container\n"
        return ""

    opps = _check_lateral_movement("10.0.0.9", _SHELL, run_cmd=run)
    # the routes probe failed but docker still produced an opportunity
    assert any(o["type"] == "docker_access" for o in opps)


def test_excludes_own_32():
    opps = _check_lateral_movement(
        "10.0.0.9", _SHELL, run_cmd=lambda c: "10.0.0.9/32 dev lo\n" if "ip route" in c else ""
    )
    assert all(o.get("target_network") != "10.0.0.9/32" for o in opps)
