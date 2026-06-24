"""The creds+SSH foothold rule now doubles as a deterministic linpeas-lite: one SSH round-trip runs
sudo -ln + SUID + capabilities + cron and flags GTFOBins-known vectors as [PRIVESC-VECTOR], turning a
user shell into a root path without the model fumbling the privesc enumeration."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_ssh_with_creds, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_FOOTHOLD = ExtractedFacts(creds=(("dale", "Password123"),), services=((22, "ssh"),))


def test_runs_full_privesc_enum_in_one_round_trip():
    rec = _rule_ssh_with_creds(_FOOTHOLD, [], "")
    assert rec is not None and rec.confidence >= 0.92
    for needle in ("sudo -ln", "perm -4000", "getcap", "/etc/crontab", "PRIVESC-VECTOR"):
        assert needle in rec.args


def test_flags_gtfobins_known_vectors():
    rec = _rule_ssh_with_creds(_FOOTHOLD, [], "")
    # a spread of GTFOBins-exploitable sudo/SUID binaries + capabilities must be in the flagging grep
    for binary in ("python", "find", "vim", "tar", "nmap", "pkexec", "openssl"):
        assert binary in rec.args
    assert "cap_setuid" in rec.args and "NOPASSWD" in rec.args


def test_abstains_without_creds_or_ssh():
    assert _rule_ssh_with_creds(ExtractedFacts(services=((22, "ssh"),)), [], "") is None
    # creds but SMB-only (no SSH) → don't ssh blindly
    assert _rule_ssh_with_creds(ExtractedFacts(creds=(("x", "y"),), services=((445, "smb"),)), [], "") is None


def test_abstains_once_ssh_attempted():
    assert _rule_ssh_with_creds(_FOOTHOLD, ["sshpass -p ... ssh dale@..."], "") is None


def test_plan_selects_foothold_on_creds():
    rec = plan_next_action(_FOOTHOLD, prior_tool_args=[], intent="")
    assert rec is not None and "PRIVESC-VECTOR" in rec.args
