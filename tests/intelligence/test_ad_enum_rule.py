"""Deterministic AD entry: DC fingerprint -> self-contained domain+user enum (ldapsearch
rootDSE + kerbrute), parsed into facts.domains/users so the AS-REP-roast chain fires without
the model driving the enum. Validated live on THM AttacktiveDirectory (spookysec.local;
svc-admin/backup). This is the AD analogue of web-loot — knowledge/enum in the tools, not the model.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_ad_enum_domain_users,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts, extract_facts

_DC = ExtractedFacts(services=((88, "kerberos-sec"), (389, "ldap"), (445, "microsoft-ds")))


def test_fires_on_dc_fingerprint():
    rec = _rule_ad_enum_domain_users(_DC, [], "")
    assert rec is not None
    assert rec.confidence >= 0.92
    assert "ldapsearch" in rec.args and "kerbrute userenum" in rec.args


def test_abstains_without_dc_ports():
    assert _rule_ad_enum_domain_users(ExtractedFacts(services=((80, "http"),)), [], "") is None
    # SMB alone is not a DC (needs Kerberos + LDAP).
    assert _rule_ad_enum_domain_users(ExtractedFacts(services=((445, "smb"),)), [], "") is None


def test_abstains_when_users_known():
    f = ExtractedFacts(services=((88, "k"), (389, "l")), users=("svc-admin",))
    assert _rule_ad_enum_domain_users(f, [], "") is None


def test_abstains_when_already_run():
    assert _rule_ad_enum_domain_users(_DC, ["kerbrute userenum -d x"], "") is None


def test_full_chain_enum_output_feeds_asreproast():
    """The autoexec'd command's output must parse into facts.domains/users so the next planner
    call returns the AS-REP-roast directive — the whole point of the rule."""
    enum_output = (
        "namingContexts: DC=spookysec,DC=local\n"
        "[+] VALID USERNAME:\t svc-admin@spookysec.local\n"
        "[+] VALID USERNAME:\t backup@spookysec.local\n"
    )
    facts = _DC.merge(extract_facts("run_command", enum_output))
    assert "spookysec.local" in facts.domains
    assert "svc-admin" in facts.users and "backup" in facts.users
    # AD-enum now abstains (users known); the planner advances to AS-REP roasting.
    nxt = plan_next_action(facts, prior_tool_args=["kerbrute userenum -d spookysec.local"], intent="")
    assert nxt is not None
    assert "GetNPUsers" in nxt.args
