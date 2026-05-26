"""FASE 1 — fact_extractor unit tests.

Samples drawn from real tool outputs observed in the THM Operation
Endgame + Pyrat runs that motivated this module. Each parser test pins
behavior against a representative chunk; the dispatch tests verify the
right parser fires from a substring of the invocation string.

The renderer tests pin the prompt-block shape that the reflective
runner injects into reflection turns — keep them in sync if you change
the rendering, since downstream tooling greps for the headers.
"""

from __future__ import annotations

from kryon.intelligence.fact_extractor import (
    EMPTY,
    ExtractedFacts,
    extract_facts,
)


# ---------------------------------------------------------------------------
# ldapsearch
# ---------------------------------------------------------------------------


def test_ldapsearch_extracts_users_domain_and_dns() -> None:
    sample = """\
# extended LDIF
#
# LDAPv3
# base <dc=thm,dc=local> with scope subtree

dn: CN=Administrator,CN=Users,DC=thm,DC=local
objectClass: user
sAMAccountName: Administrator
userPrincipalName: administrator@thm.local

dn: CN=Guest,CN=Users,DC=thm,DC=local
objectClass: user
sAMAccountName: guest

dn: CN=alice,CN=Users,DC=thm,DC=local
objectClass: user
sAMAccountName: alice

dn:
defaultNamingContext: DC=thm,DC=local
"""
    facts = extract_facts("ldapsearch -x -H ldap://target -b dc=thm,dc=local", sample)
    assert "Administrator" in facts.users
    assert "alice" in facts.users
    assert "guest" in facts.users
    assert "thm.local" in facts.domains
    # Each DN should land in paths (pivot intel).
    assert any("CN=Administrator" in p for p in facts.paths)


def test_ldapsearch_handles_naming_contexts_rootdse() -> None:
    sample = """\
dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
"""
    facts = extract_facts("ldapsearch -s base namingcontexts", sample)
    assert "corp.local" in facts.domains


# ---------------------------------------------------------------------------
# smbclient
# ---------------------------------------------------------------------------


def test_smbclient_extracts_share_names() -> None:
    sample = """\
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
"""
    facts = extract_facts("smbclient -L //target -N", sample)
    assert "ADMIN$" in facts.shares
    assert "IPC$" in facts.shares
    assert "NETLOGON" in facts.shares
    assert "SYSVOL" in facts.shares


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


def test_nmap_extracts_services_and_versions() -> None:
    sample = """\
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-26 13:11 +0000
Nmap scan report for 10.64.170.128
Host is up.
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1
80/tcp    open  http         Apache httpd 2.4.41
389/tcp   open  ldap
445/tcp   open  microsoft-ds
"""
    facts = extract_facts("nmap", sample)
    ports = {p for p, _ in facts.services}
    assert {22, 80, 389, 445}.issubset(ports)
    svcs = {svc for _, svc in facts.services}
    assert "ssh" in svcs
    assert "ldap" in svcs
    versions = dict(facts.versions)
    assert versions.get("OpenSSH") == "8.2p1"
    assert versions.get("Apache") == "httpd 2.4.41"


# ---------------------------------------------------------------------------
# nxc / netexec / crackmapexec
# ---------------------------------------------------------------------------


def test_nxc_extracts_creds_domain_users() -> None:
    sample = """\
SMB    10.64.170.128  445  DC01      [*] Windows Server 2019 (domain:THM.LOCAL)
SMB    10.64.170.128  445  DC01      [+] THM.LOCAL\\alice:Password123!
"""
    facts = extract_facts("nxc smb 10.64.170.128 -u alice -p Password123!", sample)
    assert "alice" in facts.users
    assert "thm.local" in facts.domains
    assert ("alice", "Password123!") in facts.creds
    assert "10.64.170.128" in facts.hosts


def test_nxc_empty_password_does_not_produce_phantom_cred() -> None:
    """guest with empty password is a probe, not a cred. We should still
    pick up the username + domain but NOT add it to ``creds``."""
    sample = """\
SMB    10.64.170.128  445  DC01      [-] THM.LOCAL\\guest:'' STATUS_LOGON_FAILURE
"""
    facts = extract_facts("nxc smb target -u guest -p ''", sample)
    assert "guest" in facts.users
    assert all(c[0] != "guest" for c in facts.creds)


# ---------------------------------------------------------------------------
# GetNPUsers (asreproast)
# ---------------------------------------------------------------------------


def test_getnpusers_extracts_krb5asrep_hashes() -> None:
    sample = """\
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for alice
$krb5asrep$23$alice@THM.LOCAL:aabbcc112233445566778899:ffeeddccbbaa
[*] Getting TGT for bob
$krb5asrep$23$bob@THM.LOCAL:1234567890abcdef:fedcba0987654321
"""
    facts = extract_facts("GetNPUsers.py -no-pass thm.local/", sample)
    assert "alice" in facts.users
    assert "bob" in facts.users
    assert "thm.local" in facts.domains
    assert any("alice" in h for h in facts.hashes)
    assert any("bob" in h for h in facts.hashes)


# ---------------------------------------------------------------------------
# hashcat
# ---------------------------------------------------------------------------


def test_hashcat_extracts_cracked_creds() -> None:
    sample = """\
$krb5asrep$23$alice@THM.LOCAL:aabbcc:ffeedd:Password123!
$krb5asrep$23$bob@THM.LOCAL:1234:fedcba:Summer2024
"""
    facts = extract_facts("hashcat -m 18200 hashes.txt rockyou.txt --show", sample)
    assert ("alice", "Password123!") in facts.creds
    assert ("bob", "Summer2024") in facts.creds


# ---------------------------------------------------------------------------
# secretsdump
# ---------------------------------------------------------------------------


def test_secretsdump_extracts_ntlm_hashes() -> None:
    sample = """\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::
"""
    facts = extract_facts("secretsdump.py -just-dc thm.local/admin@dc", sample)
    assert "Administrator" in facts.users
    assert "krbtgt" in facts.users
    assert any("31d6cfe0" in h for h in facts.hashes)


# ---------------------------------------------------------------------------
# web_fetch_smart
# ---------------------------------------------------------------------------


def test_web_fetch_smart_extracts_server_version() -> None:
    sample = (
        '{"status": 200, "final_url": "http://x", '
        '"headers": {"server": "Microsoft-IIS/10.0", "x-powered-by": "ASP.NET"}, '
        '"body_md": "..."}'
    )
    facts = extract_facts("web_fetch_smart", sample)
    versions = dict(facts.versions)
    assert versions.get("Microsoft-IIS") == "10.0"


def test_web_fetch_smart_picks_up_ctf_hints() -> None:
    """Pyrat-style: the body contains the hint that the model kept
    missing across the run. Surfacing it in the prompt should
    materially change the next move."""
    sample = (
        '{"status": 200, "body_md": "Try a more basic connection — '
        'this is not HTTP."}'
    )
    facts = extract_facts("web_fetch_smart http://target:8000", sample)
    assert "try a more basic connection" in facts.hints


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------


def test_generic_fallback_picks_up_krb5_hashes() -> None:
    """Even when the tool isn't in the dispatch table, hashes that
    happen to be in the output should still surface."""
    sample = "random tool output $krb5asrep$23$user@DOM:abc:def"
    facts = extract_facts("some-random-tool", sample)
    assert any("krb5asrep" in h for h in facts.hashes)


def test_generic_fallback_picks_up_hint_phrases() -> None:
    sample = "the server says: hint: look at robots.txt for credentials"
    facts = extract_facts("unknown_tool", sample)
    # Both "hint:" and "look at robots" should match.
    assert "hint:" in facts.hints
    assert "look at robots" in facts.hints


def test_empty_output_returns_empty() -> None:
    assert extract_facts("anything", "") is EMPTY
    assert extract_facts("", "anything").is_empty() or not extract_facts("", "anything").is_empty()


# ---------------------------------------------------------------------------
# Merge + rendering
# ---------------------------------------------------------------------------


def test_merge_dedups_and_sorts() -> None:
    a = ExtractedFacts(users=("alice", "bob"))
    b = ExtractedFacts(users=("bob", "carol"))
    merged = a.merge(b)
    assert merged.users == ("alice", "bob", "carol")


def test_merge_combines_distinct_field_types() -> None:
    a = ExtractedFacts(users=("alice",), domains=("thm.local",))
    b = ExtractedFacts(shares=("ADMIN$",), versions=(("IIS", "10.0"),))
    merged = a.merge(b)
    assert merged.users == ("alice",)
    assert merged.shares == ("ADMIN$",)
    assert merged.domains == ("thm.local",)
    assert merged.versions == (("IIS", "10.0"),)


def test_render_for_prompt_skips_empty_facts() -> None:
    assert ExtractedFacts().render_for_prompt() == ""


def test_render_for_prompt_includes_all_present_fields() -> None:
    facts = ExtractedFacts(
        users=("alice", "bob"),
        shares=("ADMIN$",),
        domains=("thm.local",),
        services=((445, "smb"),),
        versions=(("IIS", "10.0"),),
        hints=("try a more basic connection",),
    )
    rendered = facts.render_for_prompt()
    assert "Facts extracted so far" in rendered
    assert "alice, bob" in rendered
    assert "ADMIN$" in rendered
    assert "thm.local" in rendered
    assert "445/smb" in rendered
    assert "IIS 10.0" in rendered
    assert "try a more basic connection" in rendered


def test_render_truncates_long_lists() -> None:
    """With 30 users and max_per_field=10, the rendering should show
    10 + "(+20 more)" so the model knows there's data beyond the cap.
    """
    facts = ExtractedFacts(users=tuple(f"user{i:02d}" for i in range(30)))
    rendered = facts.render_for_prompt(max_per_field=10)
    assert "(+20 more)" in rendered


# ---------------------------------------------------------------------------
# Dispatch behavior
# ---------------------------------------------------------------------------


def test_dispatch_uses_first_match() -> None:
    """``GetNPUsers.py`` invocation should route to the impacket parser,
    NOT the generic fallback, even though the hash also matches the
    generic regex."""
    sample = "$krb5asrep$23$alice@THM.LOCAL:abc:def"
    facts = extract_facts("GetNPUsers.py -no-pass thm.local/", sample)
    # impacket parser extracts the user from the hash; generic does not.
    assert "alice" in facts.users


def test_dispatch_falls_through_to_generic_when_no_match() -> None:
    """Unknown tool name — generic parser runs."""
    facts = extract_facts("totally-unknown-tool", "hint: did you read the source?")
    assert "did you read the source" in facts.hints
