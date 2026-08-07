"""Tier-3 long-tail chain-planner rules — AD CS ESC, BloodHound, GPP cpassword, NTLM-relay targets,
GraphQL introspection, NFS no_root_squash. Each is fact-gated + one-shot; we check it fires on the
right facts, abstains otherwise, guards against re-invocation, and emits the expected tool marker.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_adcs_esc,
    _rule_banner_cve_oneshots,
    _rule_bloodhound_collect,
    _rule_cred_spray_all_hosts,
    _rule_gpp_cpassword,
    _rule_graphql_introspection,
    _rule_idor_harvest,
    _rule_jenkins_groovy_rce,
    _rule_jwt_forge,
    _rule_linux_privesc_vectors,
    _rule_nfs_no_root_squash,
    _rule_ntlm_relay_targets,
    _rule_ssrf_cloud_metadata,
    _rule_windows_privesc_enum,
    _rule_xxe_probe,
    _rule_zerologon_printnightmare,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

_AD = ExtractedFacts(
    creds=(("svc", "Passw0rd"),),
    domains=("thm.local",),
    hosts=("10.0.0.1",),
    services=((389, "ldap"), (445, "microsoft-ds"), (88, "kerberos")),
)
_EMPTY = ExtractedFacts()


# --- AD long tail (gated on creds + domain) -----------------------------------------------


def test_adcs_esc_fires_and_guards():
    rec = _rule_adcs_esc(_AD, [], "")
    assert rec is not None and rec.tool == "run_command"
    assert "certipy" in rec.args and "vulnerable" in rec.args
    assert _rule_adcs_esc(_EMPTY, [], "") is None
    assert _rule_adcs_esc(_AD, ["certipy find ran"], "") is None  # re-invocation guard


def test_bloodhound_fires_and_guards():
    rec = _rule_bloodhound_collect(_AD, [], "")
    assert rec is not None and "bloodhound-python" in rec.args
    assert _rule_bloodhound_collect(_EMPTY, [], "") is None
    assert _rule_bloodhound_collect(_AD, ["bloodhound-python -u x"], "") is None


def test_gpp_cpassword_fires_and_guards():
    rec = _rule_gpp_cpassword(_AD, [], "")
    assert rec is not None and "gpp_password" in rec.args
    assert _rule_gpp_cpassword(_EMPTY, [], "") is None
    assert _rule_gpp_cpassword(_AD, ["... cpassword ..."], "") is None


def test_adcs_abstains_without_domain():
    no_domain = ExtractedFacts(creds=(("u", "p"),), services=((389, "ldap"),))
    assert _rule_adcs_esc(no_domain, [], "") is None


# --- NTLM relay (gated on SMB open, creds optional) ---------------------------------------


def test_ntlm_relay_fires_on_smb():
    rec = _rule_ntlm_relay_targets(_AD, [], "")
    assert rec is not None and "gen-relay-list" in rec.args and "ntlmrelayx" in rec.args
    assert _rule_ntlm_relay_targets(_EMPTY, [], "") is None
    assert _rule_ntlm_relay_targets(_AD, ["ntlmrelayx -tf"], "") is None


# --- GraphQL introspection (gated on a /graphql path + web) -------------------------------


def test_graphql_fires_on_graphql_path():
    gql = ExtractedFacts(paths=("/graphql",), services=((80, "http"),))
    rec = _rule_graphql_introspection(gql, [], "")
    assert rec is not None and "__schema" in rec.args
    assert _rule_graphql_introspection(_EMPTY, [], "") is None
    assert _rule_graphql_introspection(gql, ["__schema query"], "") is None


def test_graphql_abstains_without_graphql_signal():
    plain = ExtractedFacts(paths=("/login",), services=((80, "http"),))
    assert _rule_graphql_introspection(plain, [], "") is None


# --- NFS no_root_squash (gated on NFS 2049/111) -------------------------------------------


def test_nfs_fires_on_nfs_port():
    nfs = ExtractedFacts(services=((2049, "nfs"),), hosts=("10.0.0.2",))
    rec = _rule_nfs_no_root_squash(nfs, [], "")
    assert rec is not None and "showmount" in rec.args and "no_root_squash" in rec.args
    assert _rule_nfs_no_root_squash(_EMPTY, [], "") is None
    assert _rule_nfs_no_root_squash(nfs, ["showmount -e ran"], "") is None


# --- Tier-3 part 2: web long tail ---------------------------------------------------------

_WEB = ExtractedFacts(services=((80, "http"),))


def test_jwt_forge_fires_on_token_seen():
    rec = _rule_jwt_forge(_WEB, ["captured eyJhbGciOiJIUzI1NiJ9..."], "")
    assert rec is not None and "jwt_tool" in rec.args
    assert _rule_jwt_forge(_WEB, [], "") is None  # no token → abstain
    assert _rule_jwt_forge(_WEB, ["eyJ...", "jwt_tool ran"], "") is None  # guard


def test_xxe_fires_on_xml_endpoint():
    xml = ExtractedFacts(paths=("/api/xml",), services=((80, "http"),))
    rec = _rule_xxe_probe(xml, [], "")
    assert rec is not None and "DOCTYPE" in rec.args and "file:///etc/passwd" in rec.args
    assert _rule_xxe_probe(_WEB, [], "") is None
    assert _rule_xxe_probe(xml, ['SYSTEM "file ran'], "") is None


def test_idor_fires_on_numeric_id_path():
    idor = ExtractedFacts(paths=("/api/user/1001",), services=((80, "http"),))
    rec = _rule_idor_harvest(idor, [], "")
    assert rec is not None and "IDOR-HARVEST" in rec.args
    assert _rule_idor_harvest(_WEB, [], "") is None  # no numeric-id path
    assert _rule_idor_harvest(idor, ["idor ran"], "") is None


def test_idor_closes_bola_cross_user_proof():
    # XBOW camino BOLA: la regla no se queda en "enum 200s" — reusa el JWT que
    # cred-reuse/mass-assign guardan (/tmp/loot_jwt), lee el objeto de OTRO
    # usuario y PRUEBA la elevación comparando el owner del objeto vs mi user id
    # (decodificado del payload del JWT). Ese es el eslabón detección→proof.
    idor = ExtractedFacts(paths=("/api/user/1001",), services=((80, "http"),), hosts=("shop.thm",))
    rec = _rule_idor_harvest(idor, [], "")
    assert rec is not None
    # reusa el token autenticado del ecosistema (no re-loguea)
    assert "/tmp/loot_jwt" in rec.args
    assert "Authorization: Bearer" in rec.args
    # proof cross-user: owner del objeto != mi user id del JWT
    assert "IDOR-BOLA" in rec.args
    assert "CROSS-USER" in rec.args
    assert "UserId" in rec.args  # extrae el dueño del objeto de la respuesta
    # hostlist real, no el placeholder literal <target> (bug corregido)
    assert "<target>" not in rec.args
    assert "shop.thm" in rec.args
    # guards heredados de cred-reuse/mass-assign (solo la corrida viva los caza):
    assert "|| true" in rec.args  # exit 0 limpio tras hit
    assert "<(!doctype|html|!--)" in rec.args  # SPA/HTML fallback filtrado


def test_jenkins_fires_on_fingerprint():
    jenk = ExtractedFacts(services=((8080, "jenkins"),))
    rec = _rule_jenkins_groovy_rce(jenk, [], "")
    assert rec is not None and "scriptText" in rec.args
    assert _rule_jenkins_groovy_rce(_WEB, [], "") is None
    assert _rule_jenkins_groovy_rce(jenk, ["Jenkins.instance ran"], "") is None


def test_ssrf_cloud_fires_on_ssrf_signal():
    ssrf = ExtractedFacts(paths=("/fetch?url=x",), services=((80, "http"),))
    rec = _rule_ssrf_cloud_metadata(ssrf, [], "")
    assert rec is not None and "169.254.169.254" in rec.args
    assert _rule_ssrf_cloud_metadata(_WEB, [], "") is None
    assert _rule_ssrf_cloud_metadata(ssrf, ["latest/meta-data ran"], "") is None


# --- Tier-3 part 2: local privesc + DC ----------------------------------------------------


def test_windows_privesc_fires_on_winrm_creds():
    win = ExtractedFacts(creds=(("u", "p"),), services=((5985, "winrm"),), hosts=("10.0.0.1",))
    rec = _rule_windows_privesc_enum(win, [], "")
    assert rec is not None and "AlwaysInstallElevated" in rec.args and "cmdkey" in rec.args
    # weak-dir-ACL check added validating THM Anthem (C:\backup is BUILTIN\Users:(WD)(AD) -> read the admin
    # password in restore.txt) — the enum used to miss sensitive dirs writable by low-priv users.
    assert "icacls C:\\backup" in rec.args and "[WIN-PRIVESC weak-dir-acl]" in rec.args
    assert _rule_windows_privesc_enum(_EMPTY, [], "") is None
    assert _rule_windows_privesc_enum(win, ["AlwaysInstallElevated ran"], "") is None


def test_windows_weak_acl_grep_flags_writable_users_not_readonly():
    """The weak-dir-acl detection grep must flag BUILTIN\\Users with write/modify/append (the Anthem
    C:\\backup case) but NOT read-only (RX) ACLs."""
    import re

    pat = re.compile(r"Users:[^\s]*\((F|M|W|AD|WD)\)")
    assert pat.search(r"BUILTIN\Users:(I)(CI)(AD)")  # Anthem: append-data -> writable
    assert pat.search(r"BUILTIN\Users:(I)(CI)(WD)")  # write-data
    assert pat.search(r"BUILTIN\Users:(M)")  # modify
    assert not pat.search(r"BUILTIN\Users:(RX)")  # read+execute only -> not a privesc


def test_linux_privesc_fires_on_ssh_creds():
    lin = ExtractedFacts(creds=(("u", "p"),), services=((22, "ssh"),))
    rec = _rule_linux_privesc_vectors(lin, [], "")
    assert rec is not None and "LD_PRELOAD" in rec.args and "systemd" in rec.args
    assert _rule_linux_privesc_vectors(_EMPTY, [], "") is None
    assert _rule_linux_privesc_vectors(lin, ["env_keep ran"], "") is None


def test_zerologon_fires_on_dc_detection_only():
    dc = ExtractedFacts(domains=("thm.local",), services=((88, "kerberos"), (389, "ldap")), hosts=("10.0.0.1",))
    rec = _rule_zerologon_printnightmare(dc, [], "")
    assert rec is not None and "zerologon" in rec.args.lower() and "VULNERABLE" in rec.args
    # detection only — must not auto-exploit (no set-empty-machine-pw command, only flagged text)
    assert "secretsdump" in rec.args  # mentioned as operator next-step, behind KRYON_RED_TEAM note
    assert "KRYON_RED_TEAM" in rec.args
    assert _rule_zerologon_printnightmare(_EMPTY, [], "") is None
    assert _rule_zerologon_printnightmare(dc, ["zerologon ran"], "") is None


# --- 3-tier roadmap / Tier 2 -------------------------------------------------------------


def test_cred_spray_all_hosts_fans_out_and_guards():
    """Looted cred + >=2 hosts -> spray across every host x SSH/SMB/WinRM. The #1 lateral multiplier."""
    multi = ExtractedFacts(creds=(("svc", "Passw0rd"),), hosts=("10.0.0.1", "10.0.0.2", "10.0.0.3"))
    rec = _rule_cred_spray_all_hosts(multi, [], "")
    assert rec is not None and rec.confidence >= 0.9
    assert "[REUSE-SSH" in rec.args and "[REUSE-SMB" in rec.args and "[REUSE-WINRM" in rec.args
    assert "10.0.0.1" in rec.args and "10.0.0.3" in rec.args  # fans across all hosts, not just [0]
    # single host -> per-service rules already cover it; abstain. And guard against re-invocation.
    assert _rule_cred_spray_all_hosts(ExtractedFacts(creds=(("u", "p"),), hosts=("10.0.0.1",)), [], "") is None
    assert _rule_cred_spray_all_hosts(multi, ["[REUSE-SSH 10.0.0.1] uid=0"], "") is None
    assert _rule_cred_spray_all_hosts(ExtractedFacts(hosts=("a", "b")), [], "") is None  # no creds


def test_banner_cve_oneshots_has_modern_catalog():
    """The legacy-only one-shot catalog now includes the modern high-frequency RCEs."""
    rec = _rule_banner_cve_oneshots(ExtractedFacts(services=((80, "http"), (445, "smb")), hosts=("x",)), [], "")
    assert rec is not None
    assert "CVE-2022-26134" in rec.args  # Confluence OGNL (auto-probed via X-Cmd-Response)
    assert "CVE-2021-22205" in rec.args  # GitLab ExifTool (fingerprint -> flag)
    assert "CVE-2022-22965" in rec.args  # Spring4Shell (fingerprint -> flag)
    assert "MS17-010" in rec.args  # EternalBlue stays detection-only (BSOD risk)
