"""Tier-1 foothold rules (gap-roadmap): SMB null-share loot, unauth Redis RCE, .git dump, Tomcat
Manager WAR, and banner-matched one-shot CVEs. Each fires on its service signature and emits a
deterministic detect→exploit→harvest command. See docs/OFFENSIVE_RULE_GAPS.md."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_banner_cve_oneshots,
    _rule_git_dump_secrets,
    _rule_redis_unauth_rce,
    _rule_smb_null_share_loot,
    _rule_tomcat_manager_war,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

H = ("10.0.0.1",)


def test_smb_loot_fires_on_445_and_loots():
    rec = _rule_smb_null_share_loot(ExtractedFacts(services=((445, "microsoft-ds"),), hosts=H), [], "")
    assert rec is not None and "smbclient" in rec.args and "SMB-LOOT" in rec.args
    assert "id_rsa" in rec.args and "unattend" in rec.args  # loots the cred-bearing files
    assert _rule_smb_null_share_loot(ExtractedFacts(services=((80, "http"),), hosts=H), [], "") is None


def test_redis_fires_on_6379_writes_webshell():
    rec = _rule_redis_unauth_rce(ExtractedFacts(services=((6379, "redis"),), hosts=H), [], "")
    assert rec is not None and "PING" in rec.args and "CONFIG SET dir" in rec.args
    assert "kr.php" in rec.args and "uid=[0-9]" in rec.args  # verifies the shell with id
    assert _rule_redis_unauth_rce(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_git_dump_fires_on_http_and_confirms_head():
    rec = _rule_git_dump_secrets(ExtractedFacts(services=((80, "http"),), hosts=H), [], "")
    assert rec is not None and "/.git/HEAD" in rec.args and "GIT-DUMP" in rec.args
    assert "PRIVATE KEY" in rec.args  # greps the tree for secrets
    assert _rule_git_dump_secrets(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_tomcat_manager_sprays_and_deploys():
    rec = _rule_tomcat_manager_war(ExtractedFacts(services=((8080, "http"),), hosts=H), [], "")
    assert rec is not None and "/manager/" in rec.args and "tomcat:tomcat" in rec.args
    assert "deploy" in rec.args and "cmd.jsp" in rec.args  # deploys the JSP webshell WAR
    assert _rule_tomcat_manager_war(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_banner_cve_matches_open_services():
    rec = _rule_banner_cve_oneshots(ExtractedFacts(services=((21, "ftp"), (80, "http"), (445, "smb")), hosts=H), [], "")
    assert rec is not None and "BANNER-CVE" in rec.args
    for marker in ("Shellshock", "ProFTPd", "UnrealIRCd", "ms17-010"):
        assert marker in rec.args
    assert _rule_banner_cve_oneshots(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_all_abstain_once_run():
    f = ExtractedFacts(services=((445, "smb"), (6379, "redis"), (80, "http"), (8080, "http"), (21, "ftp")), hosts=H)
    assert _rule_smb_null_share_loot(f, ["[SMB-LOOT //x/y]"], "") is None
    assert _rule_redis_unauth_rce(f, ["[REDIS-RCE ...]"], "") is None
    assert _rule_git_dump_secrets(f, ["[GIT-DUMP ...]"], "") is None
    assert _rule_tomcat_manager_war(f, ["[TOMCAT-MGR ...]"], "") is None
    assert _rule_banner_cve_oneshots(f, ["[BANNER-CVE ...]"], "") is None
