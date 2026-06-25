"""Tier-1 privesc rules: linpeas_autoexploit (flag→exploit→root) + cred_harvest_reuse. Both fire on
creds+SSH and chain AFTER ssh_with_creds via their own markers (linpeas_auto / cred_harvest)."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_cred_harvest_reuse,
    _rule_linpeas_autoexploit,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

_CREDS = ExtractedFacts(services=((22, "ssh"),), hosts=("10.0.0.1",), creds=(("bob", "pw123"),))


def test_linpeas_autoexploits_root_vectors():
    rec = _rule_linpeas_autoexploit(_CREDS, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "sshpass -p 'pw123'" in rec.args and "linpeas_auto" in rec.args
    # auto-exploits docker/sudo, flags lxd/cap/writable-passwd, grabs user flag
    assert "docker-group" in rec.args and "sudo-nopasswd" in rec.args
    assert "cap_setuid" in rec.args and "USER-FLAG" in rec.args


def test_cred_harvest_sweeps_fs():
    rec = _rule_cred_harvest_reuse(_CREDS, [], "")
    assert rec is not None and "CRED-FOUND" in rec.args
    assert "bash_history" in rec.args and "id_rsa" in rec.args  # history + keys


def test_both_need_creds_and_ssh():
    assert _rule_linpeas_autoexploit(ExtractedFacts(services=((22, "ssh"),), hosts=("x",)), [], "") is None
    no_ssh = ExtractedFacts(services=((445, "smb"),), hosts=("x",), creds=(("a", "b"),))
    assert _rule_linpeas_autoexploit(no_ssh, [], "") is None
    assert _rule_cred_harvest_reuse(no_ssh, [], "") is None


def test_linpeas_fires_after_ssh_with_creds():
    # key chain link: with creds + SSH and ssh_with_creds already run (sshpass marker), the planner
    # advances to linpeas_autoexploit (no web/foothold service to preempt).
    after_ssh = plan_next_action(
        _CREDS, prior_tool_args=["nmap ... (service_scan)", "sshpass ... [PRIVESC-VECTOR]"], intent=""
    )
    assert after_ssh is not None and "linpeas_auto" in after_ssh.args
    # once linpeas has run too, it abstains (its marker) and cred_harvest is eligible
    assert _rule_linpeas_autoexploit(_CREDS, [": linpeas_auto; [ROOT docker-group] x"], "") is None
    assert _rule_cred_harvest_reuse(_CREDS, [], "") is not None


def test_abstain_once_run():
    assert _rule_linpeas_autoexploit(_CREDS, [": linpeas_auto; [ROOT ...]"], "") is None
    assert _rule_cred_harvest_reuse(_CREDS, [": cred_harvest; [CRED-FOUND ...]"], "") is None
