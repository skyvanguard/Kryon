"""Tier-2 rules from the gap roadmap: unauth/weak DB RCE, WordPress wpscan, SNMP/SMTP user enum, SMB
RID cycling, and one-file privesc CVE version-match. See docs/OFFENSIVE_RULE_GAPS.md."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_db_unauth_rce,
    _rule_privesc_cve_check,
    _rule_rid_cycle_then_roast,
    _rule_snmp_smtp_user_enum,
    _rule_wordpress_wpscan,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

H = ("10.0.0.1",)


def test_db_unauth_fires_on_db_ports():
    rec = _rule_db_unauth_rce(ExtractedFacts(services=((3306, "mysql"), (27017, "mongodb")), hosts=H), [], "")
    assert rec is not None and "DB-RCE" in rec.args
    assert "mysql.user" in rec.args and "listDatabases" in rec.args  # mysql dump + mongo
    assert _rule_db_unauth_rce(ExtractedFacts(services=((80, "http"),), hosts=H), [], "") is None


def test_db_unauth_covers_mssql_postgres():
    rec = _rule_db_unauth_rce(ExtractedFacts(services=((1433, "mssql"), (5432, "postgres")), hosts=H), [], "")
    assert "xp_cmdshell" in rec.args and "COPY FROM PROGRAM" in rec.args


def test_wordpress_confirms_then_scans():
    rec = _rule_wordpress_wpscan(ExtractedFacts(services=((80, "http"),), hosts=H), [], "")
    assert rec is not None and "wp-content" in rec.args and "wpscan" in rec.args
    assert "-e u,vp,vt" in rec.args  # users + vuln plugins/themes
    assert _rule_wordpress_wpscan(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_snmp_smtp_enum_fires_on_161_or_25():
    rec = _rule_snmp_smtp_user_enum(ExtractedFacts(services=((161, "snmp"), (25, "smtp")), hosts=H), [], "")
    assert rec is not None and "snmpwalk" in rec.args and "VRFY" in rec.args
    assert "USER-ENUM" in rec.args
    assert _rule_snmp_smtp_user_enum(ExtractedFacts(services=((80, "http"),), hosts=H), [], "") is None


def test_rid_cycle_fires_on_smb_thin_userlist():
    rec = _rule_rid_cycle_then_roast(ExtractedFacts(services=((445, "microsoft-ds"),), hosts=H, domains=("thm.local",)), [], "")
    assert rec is not None and "rid-brute" in rec.args and "RID-USERS" in rec.args
    assert "/tmp/users.txt" in rec.args  # feeds the roast
    # abstains when a user list already exists
    fat = ExtractedFacts(services=((445, "smb"),), hosts=H, users=("a", "b", "c", "d", "e", "f"))
    assert _rule_rid_cycle_then_roast(fat, [], "") is None


def test_privesc_cve_version_matches():
    rec = _rule_privesc_cve_check(ExtractedFacts(services=((22, "ssh"),), hosts=H, creds=(("bob", "pw"),)), [], "")
    assert rec is not None and "sshpass -p 'pw'" in rec.args
    for cve in ("CVE-2021-4034", "CVE-2021-3156", "CVE-2022-0847", "CVE-2016-5195"):
        assert cve in rec.args
    assert _rule_privesc_cve_check(ExtractedFacts(services=((445, "smb"),), hosts=H, creds=(("a", "b"),)), [], "") is None


def test_all_abstain_once_run():
    assert _rule_db_unauth_rce(ExtractedFacts(services=((3306, "mysql"),), hosts=H), ["[DB-RCE ...]"], "") is None
    assert _rule_wordpress_wpscan(ExtractedFacts(services=((80, "http"),), hosts=H), ["[WP-SCAN ...]"], "") is None
    assert _rule_snmp_smtp_user_enum(ExtractedFacts(services=((161, "snmp"),), hosts=H), ["[USER-ENUM ...]"], "") is None
    rid = ExtractedFacts(services=((445, "smb"),), hosts=H)
    assert _rule_rid_cycle_then_roast(rid, ["[RID-USERS]"], "") is None
    assert _rule_privesc_cve_check(ExtractedFacts(services=((22, "ssh"),), hosts=H, creds=(("a", "b"),)), ["[PRIVESC-CVE ...]"], "") is None
