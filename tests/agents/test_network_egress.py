"""Network egress cage — iptables lockdown generated from the scope.

Defense-in-depth below the scope gate: caps EVERY process in the container at the
OS level, catching subprocess tools and obfuscated targets the regex gate misses.
"""

from __future__ import annotations

from kryon.agents.network_egress import (
    apply_egress,
    build_iptables_commands,
    main,
)


def _joined(cmds):
    return [" ".join(c) for c in cmds]


def test_ruleset_shape_and_default_drop():
    cmds = _joined(build_iptables_commands(["10.65.168.0/24"], [], []))
    assert cmds[0] == "iptables -F OUTPUT"  # flush first
    assert "iptables -A OUTPUT -o lo -j ACCEPT" in cmds  # loopback
    assert any("ESTABLISHED,RELATED" in c for c in cmds)  # stateful
    assert any("--dport 53" in c for c in cmds)  # DNS
    assert "iptables -A OUTPUT -d 10.65.168.0/24 -j ACCEPT" in cmds  # scope allowed
    assert cmds[-1] == "iptables -A OUTPUT -j DROP"  # default deny last


def test_deny_is_a_drop_rule_before_scope_accept():
    cmds = _joined(build_iptables_commands(["10.0.0.0/24"], ["10.0.0.1"], []))
    deny_i = cmds.index("iptables -A OUTPUT -d 10.0.0.1 -j DROP")
    accept_i = cmds.index("iptables -A OUTPUT -d 10.0.0.0/24 -j ACCEPT")
    assert deny_i < accept_i  # deny evaluated before the broad allow


def test_infra_is_allowed():
    cmds = _joined(build_iptables_commands(["10.0.0.0/24"], [], ["172.20.0.0/24"]))
    assert "iptables -A OUTPUT -d 172.20.0.0/24 -j ACCEPT" in cmds


def test_apply_dry_run_returns_rules(monkeypatch):
    monkeypatch.setenv("KRYON_SCOPE", "10.65.168.0/24")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("KRYON_SCOPE_DENY", raising=False)
    monkeypatch.delenv("KRYON_INFRA_ALLOW", raising=False)
    ok, msg = apply_egress(dry_run=True)
    assert ok is True
    assert "iptables -A OUTPUT -d 10.65.168.0/24 -j ACCEPT" in msg
    assert msg.strip().endswith("iptables -A OUTPUT -j DROP")


def test_no_scope_is_a_skip_not_an_error(monkeypatch):
    monkeypatch.delenv("KRYON_SCOPE", raising=False)
    ok, msg = apply_egress(dry_run=True)
    assert ok is False and "skipped" in msg


def test_main_defaults_to_dry_run(monkeypatch, capsys):
    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    rc = main([])  # no 'apply' → dry-run
    out = capsys.readouterr().out
    assert rc == 0
    assert "[dry-run]" in out and "OUTPUT -j DROP" in out


def test_openai_base_url_host_auto_allowed(monkeypatch):
    # The LLM endpoint must stay reachable or the cage starves the agent.
    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://172.20.0.5:8080/v1")
    monkeypatch.delenv("KRYON_INFRA_ALLOW", raising=False)
    monkeypatch.delenv("KRYON_SCOPE_DENY", raising=False)
    ok, msg = apply_egress(dry_run=True)
    assert "172.20.0.5" in msg  # LLM host auto-allowed


def test_resolve_url_and_domain(monkeypatch):
    import kryon.agents.network_egress as ne

    monkeypatch.setattr(ne.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert ne._resolve_to_cidr("http://example.com/path") == "93.184.216.34"
    assert ne._resolve_to_cidr("*.example.com") == "93.184.216.34"
    assert ne._resolve_to_cidr("10.0.0.0/24") == "10.0.0.0/24"  # already a CIDR
    assert ne._resolve_to_cidr("") is None


def test_resolve_unresolvable_returns_none(monkeypatch):
    import socket

    import kryon.agents.network_egress as ne

    def _boom(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(ne.socket, "getaddrinfo", _boom)
    assert ne._resolve_to_cidr("nonexistent.invalid") is None


def test_apply_non_dry_run_success(monkeypatch):
    import kryon.agents.network_egress as ne

    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    calls = []
    monkeypatch.setattr(ne.subprocess, "run", lambda c, **k: calls.append(c))
    ok, msg = ne.apply_egress(dry_run=False)
    assert ok is True and "applied" in msg and len(calls) > 0


def test_apply_non_dry_run_failure(monkeypatch):
    import kryon.agents.network_egress as ne

    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    def _boom(c, **k):
        raise OSError("iptables: Permission denied")

    monkeypatch.setattr(ne.subprocess, "run", _boom)
    ok, msg = ne.apply_egress(dry_run=False)
    assert ok is False and "FAILED" in msg


def test_main_apply_path(monkeypatch, capsys):
    import kryon.agents.network_egress as ne

    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(ne.subprocess, "run", lambda c, **k: None)
    rc = ne.main(["apply"])
    assert rc == 0
    assert "[dry-run]" not in capsys.readouterr().out
