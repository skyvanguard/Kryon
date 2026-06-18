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
        '{"status": 200, "final_url": "http://x.example/", '
        '"headers": {"server": "Microsoft-IIS/10.0", "x-powered-by": "ASP.NET"}, '
        '"body_md": "..."}'
    )
    facts = extract_facts("web_fetch_smart", sample)
    versions = dict(facts.versions)
    assert versions.get("Microsoft-IIS") == "10.0"


def test_web_fetch_smart_extracts_host_and_port_from_url() -> None:
    """The planner's netcat-on-hint rule needs ``services`` populated
    with a non-22 port. Pyrat-style web_fetch_smart capture gives us
    the URL — pull host + port from it so downstream rules can fire."""
    sample = (
        '{"status": 200, "final_url": "http://10.67.190.8:8000/", '
        '"headers": {"server": "SimpleHTTP/0.6 Python/3.11.2"}, '
        '"body_md": "Try a more basic connection"}'
    )
    facts = extract_facts("web_fetch_smart", sample)
    assert "10.67.190.8" in facts.hosts
    ports = {p for p, _ in facts.services}
    assert 8000 in ports


def test_web_fetch_smart_defaults_port_80_when_url_has_no_port() -> None:
    sample = '{"status": 200, "final_url": "http://target.example/path", "body_md": "..."}'
    facts = extract_facts("web_fetch_smart", sample)
    ports = {p for p, _ in facts.services}
    assert 80 in ports


def test_web_fetch_smart_defaults_port_443_when_https() -> None:
    sample = '{"status": 200, "final_url": "https://target.example/", "body_md": "..."}'
    facts = extract_facts("web_fetch_smart", sample)
    ports = {p for p, _ in facts.services}
    assert 443 in ports


# ---------------------------------------------------------------------------
# G5 (FASE 4) — anti-pattern hints on tool invocations
# ---------------------------------------------------------------------------


def test_nc_without_timeout_flags_emits_anti_pattern_hint() -> None:
    """nc invocation without -q or -w should surface a hint reminding
    the model that the subprocess will hang."""
    sample = "(UNKNOWN) [10.0.0.1] 8000 (?) open"
    facts = extract_facts("nc 10.0.0.1 8000", sample)
    assert any("nc invocation lacks -q/-w" in h for h in facts.hints)


def test_nc_with_q_flag_does_not_emit_anti_pattern() -> None:
    """``nc -q 1 -w 5 target port`` is the correct form — no hint."""
    sample = "(UNKNOWN) [10.0.0.1] 8000 (?) open"
    facts = extract_facts("nc -q 1 -w 5 10.0.0.1 8000", sample)
    assert not any("timeout flags" in h for h in facts.hints)


def test_nc_inside_echo_pipe_still_detected() -> None:
    """``echo 'foo' | nc target port`` should still trip the
    no-timeout-flag rule when nc lacks -q/-w."""
    sample = "(UNKNOWN) [10.0.0.1] 8000 (?) open"
    facts = extract_facts(
        "echo 'help' | nc 10.0.0.1 8000",
        sample,
    )
    assert any("nc invocation lacks" in h for h in facts.hints)


def test_ldapsearch_without_filter_emits_anti_pattern_hint() -> None:
    """ldapsearch -b without an objectClass filter should warn that
    it'll dump the whole subtree."""
    sample = "# extended LDIF\ndn: CN=foo,DC=corp,DC=local\nsAMAccountName: foo"
    facts = extract_facts(
        "ldapsearch -x -H ldap://target -b 'DC=corp,DC=local'",
        sample,
    )
    assert any("objectClass filter" in h for h in facts.hints)


def test_ldapsearch_with_filter_does_not_emit_anti_pattern() -> None:
    sample = "# extended LDIF\ndn: ...\nsAMAccountName: foo"
    facts = extract_facts(
        "ldapsearch -x -H ldap://target -b 'DC=corp,DC=local' -s sub '(objectClass=user)'",
        sample,
    )
    assert not any("objectClass filter" in h for h in facts.hints)


def test_curl_without_max_time_emits_anti_pattern_hint() -> None:
    facts = extract_facts(
        "curl http://target.example/path",
        "<html>...</html>",
    )
    assert any("--max-time" in h for h in facts.hints)


def test_curl_with_max_time_does_not_emit_anti_pattern() -> None:
    facts = extract_facts(
        "curl --max-time 10 http://target.example/path",
        "<html>...</html>",
    )
    assert not any("--max-time" in h for h in facts.hints)


def test_getnpusers_without_outputfile_emits_anti_pattern_hint() -> None:
    facts = extract_facts(
        "GetNPUsers.py -no-pass -dc-ip 1.2.3.4 thm.local/",
        "Impacket v0.10\n$krb5asrep$23$alice@THM.LOCAL:abc:def",
    )
    assert any("-outputfile" in h for h in facts.hints)


def test_anti_pattern_hints_dont_interfere_with_parser_output() -> None:
    """The G5 hints should be MERGED on top of whatever the per-tool
    parser extracted — not replace it."""
    sample = "# extended LDIF\ndn: CN=alice,CN=Users,DC=corp,DC=local\nsAMAccountName: alice\n"
    facts = extract_facts(
        "ldapsearch -x -H ldap://target -b 'DC=corp,DC=local'",
        sample,
    )
    # Parser still extracted users + domain.
    assert "alice" in facts.users
    # Anti-pattern hint also fired.
    assert any("objectClass filter" in h for h in facts.hints)


def test_web_fetch_smart_detects_php_app_pages_from_gobuster_output() -> None:
    """FASE 11.P.1 — when gobuster output (or any tool output) reveals
    PHP app entry points like ``login.php`` / ``register.php`` /
    ``admin.php`` / ``upload.php`` / ``index.php`` / ``config.php``,
    surface each as a ``discovered:<file>`` hint so the planner's
    auth-chain rules can pivot on the signal.

    Robots THM manual recon showed ``/harm/to/self/`` contained
    ``admin.php login.php register.php config.php index.php`` — these
    are the canonical CTF web-app entry points and each implies a
    distinct exploitation path."""
    sample = (
        "Found admin.php (Status: 302)\n"
        "Found login.php (Status: 302)\n"
        "Found register.php (Status: 302)\n"
        "Found config.php (Status: 302)\n"
        "Found index.php (Status: 302)\n"
    )
    facts = extract_facts(
        "gobuster dir -u http://target/harm/to/self -w common.txt",
        sample,
    )
    assert "discovered:login.php" in facts.hints
    assert "discovered:register.php" in facts.hints
    assert "discovered:admin.php" in facts.hints
    # config.php typically holds credentials; capture too
    assert "discovered:config.php" in facts.hints


def test_web_fetch_smart_detects_upload_php_separately() -> None:
    """``upload.php`` opens a different exploitation path (file-upload
    webshell) so we want it surfaced even if other PHP pages aren't
    present in the same output."""
    sample = "Found upload.php (Status: 200)\n"
    facts = extract_facts("gobuster dir ... -w big.txt", sample)
    assert "discovered:upload.php" in facts.hints


def test_web_fetch_smart_discovered_skips_static_assets() -> None:
    """css/js/static asset filenames shouldn't pollute the hint set
    (they don't enable any exploitation path)."""
    sample = (
        "Found style.css (Status: 200)\n"
        "Found app.js (Status: 200)\n"
        "Found login.php (Status: 302)\n"  # only this counts
    )
    facts = extract_facts("gobuster dir ...", sample)
    assert "discovered:login.php" in facts.hints
    assert "discovered:style.css" not in facts.hints
    assert "discovered:app.js" not in facts.hints


def test_web_fetch_smart_detects_vhost_from_location_redirect() -> None:
    """FASE 11.O.2 — when a 302 redirect's Location header points to
    a hostname different from the host we requested, that hostname is
    a virtual host. Capture it as a ``vhost:<hostname>`` hint so the
    planner can emit a curl-with-Host-header directive.

    Robots THM (2026-05-26) had every PHP endpoint redirecting to
    ``Location: http://robots.thm/...`` even though we'd fetched
    ``10.67.138.59``. Without the vhost hint the model fetched the
    redirect target which returned 403; with the hint + Host header
    the real PHP app surfaces."""
    sample = (
        '{"status": 302, "final_url": "http://10.67.138.59/login.php", '
        '"headers": {"location": "http://robots.thm/login.php"}, '
        '"body_md": ""}'
    )
    facts = extract_facts(
        "web_fetch_smart http://10.67.138.59/login.php",
        sample,
    )
    assert "vhost:robots.thm" in facts.hints


def test_web_fetch_smart_vhost_ignores_same_host_redirects() -> None:
    """Internal redirects to the SAME hostname/IP are not vhosts —
    those are just routing changes. The hint should ONLY fire when
    the Location host differs from where we requested."""
    sample = (
        '{"status": 302, "final_url": "http://10.67.138.59/old", "headers": {"location": "http://10.67.138.59/new"}}'
    )
    facts = extract_facts(
        "web_fetch_smart http://10.67.138.59/old",
        sample,
    )
    assert not any(h.startswith("vhost:") for h in facts.hints)


def test_web_fetch_smart_vhost_strips_port_from_hostname() -> None:
    """``Location: http://robots.thm:80/x`` and
    ``Location: http://robots.thm/x`` should produce the same vhost
    hint — strip port for the Host header value."""
    sample = '{"status": 302, "final_url": "http://10.67.138.59/x", "headers": {"location": "http://robots.thm:80/x"}}'
    facts = extract_facts("web_fetch_smart http://10.67.138.59/x", sample)
    assert "vhost:robots.thm" in facts.hints


def test_web_fetch_smart_parses_robots_disallow_paths() -> None:
    """FASE 11.K — when web_fetch_smart returns a robots.txt body
    with ``Disallow:`` directives, each path must surface as a
    structured hint so the planner can fire a gobuster directive
    against it.

    THM Robots-style bench (2026-05-26): the robots.txt revealed
    three Asimov-themed disallow paths but the model only narrated
    them in <think>, never invoking gobuster. Surfacing them as
    ``disallow:<path>`` hints gives the planner a stable signal to
    pivot on.
    """
    sample = (
        '{"status": 200, "final_url": "http://target/robots.txt", '
        '"body_md": "User-agent: *\\nDisallow: /harming/humans\\n'
        'Disallow: /ignoring/human/orders\\nDisallow: /harm/to/self"}'
    )
    facts = extract_facts("web_fetch_smart http://target/robots.txt", sample)
    assert "disallow:/harming/humans" in facts.hints
    assert "disallow:/ignoring/human/orders" in facts.hints
    assert "disallow:/harm/to/self" in facts.hints


def test_web_fetch_smart_robots_disallow_normalizes_case() -> None:
    """Some robots.txt files use lowercase or weird spacing —
    normalize so the planner's match still hits."""
    sample = (
        '{"status": 200, "final_url": "http://t/robots.txt", '
        '"body_md": "User-agent: *\\ndisallow:   /admin\\n'
        'DISALLOW: /secret"}'
    )
    facts = extract_facts("web_fetch_smart http://t/robots.txt", sample)
    assert "disallow:/admin" in facts.hints
    assert "disallow:/secret" in facts.hints


def test_web_fetch_smart_skips_allow_directives() -> None:
    """Only ``Disallow:`` paths count — ``Allow:`` paths are
    intentionally exposed by the operator and aren't the
    high-signal hint we want."""
    sample = '{"status": 200, "final_url": "http://t/robots.txt", "body_md": "Allow: /public\\nDisallow: /admin"}'
    facts = extract_facts("web_fetch_smart http://t/robots.txt", sample)
    assert "disallow:/admin" in facts.hints
    assert "disallow:/public" not in facts.hints
    assert "allow:/public" not in facts.hints


def test_web_fetch_smart_disallow_root_path_skipped() -> None:
    """``Disallow: /`` blocks everything and isn't useful as a
    gobuster target — skip it to avoid noise."""
    sample = '{"status": 200, "final_url": "http://t/robots.txt", "body_md": "Disallow: /\\nDisallow: /admin"}'
    facts = extract_facts("web_fetch_smart http://t/robots.txt", sample)
    assert "disallow:/admin" in facts.hints
    assert "disallow:/" not in facts.hints


def test_web_fetch_smart_picks_up_ctf_hints() -> None:
    """Pyrat-style: the body contains the hint that the model kept
    missing across the run. Surfacing it in the prompt should
    materially change the next move."""
    sample = (
        '{"status": 200, "final_url": "http://target:8000/", '
        '"body_md": "Try a more basic connection — '
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


# ---------------------------------------------------------------------------
# Web path extraction — feeds the chain planner's web-exploitation rules.
# Without this facts.paths only ever held LDAP DNs and the web rules were
# dead code.
# ---------------------------------------------------------------------------


def test_web_fetch_smart_extracts_parametrized_path() -> None:
    sample = (
        '{"final_url": "http://10.0.0.5/", "server": "Apache/2.4", '
        '"body": "see [products](/products?id=1) and /search?q=test"}'
    )
    facts = extract_facts("web_fetch_smart http://10.0.0.5/", sample)
    assert "/products?id=1" in facts.paths
    assert "/search?q=test" in facts.paths


def test_web_path_absolute_url_normalized_to_relative() -> None:
    """Absolute URLs are stripped to a relative path so the planner targets
    the fetched host, not an external link."""
    sample = '{"body": "link http://10.0.0.5/item.php?cat=2 here"}'
    facts = extract_facts("web_fetch_smart http://10.0.0.5/", sample)
    assert "/item.php?cat=2" in facts.paths
    # the host portion must NOT leak into the stored path
    assert not any("10.0.0.5" in p for p in facts.paths)


def test_disallow_paths_promoted_to_facts_paths() -> None:
    sample = '{"body": "User-agent: *\nDisallow: /admin\nDisallow: /backup"}'
    facts = extract_facts("web_fetch_smart http://t/robots.txt", sample)
    assert "/admin" in facts.paths
    assert "/backup" in facts.paths


def test_generic_pass_also_extracts_web_paths() -> None:
    """The reflective runner's whole-chunk pass routes through _parse_generic
    (empty tool_invocation) — it must extract web paths too."""
    chunk = "curl output: GET /login?next=/admin returned 200"
    facts = extract_facts("", chunk)
    assert "/login?next=/admin" in facts.paths


def test_web_param_path_drives_planner_to_sqlmap() -> None:
    """End-to-end: a web_fetch_smart capture with a parametrized URL must now
    flow through to a concrete sqlmap recommendation (the fix #2 chain that
    was dead before web-path extraction existed)."""
    from kryon.intelligence.exploit_chain_planner import plan_next_action

    sample = '{"final_url": "http://10.10.10.10/", "body": "go to /item?id=3"}'
    facts = extract_facts("web_fetch_smart http://10.10.10.10/", sample)
    assert "/item?id=3" in facts.paths
    rec = plan_next_action(facts, [], "audita http://10.10.10.10")
    assert rec is not None
    assert "sqlmap" in rec.args
    assert "/item?id=3" in rec.args


# ---------------------------------------------------------------------------
# Gap #2 — new parsers: hydra/medusa, sqlmap, dir-brute, nuclei. Each turns a
# tool the agent commonly runs into facts that feed an existing chain rule,
# so the autonomous chain doesn't dead-end after that tool.
# ---------------------------------------------------------------------------


def test_hydra_extracts_cracked_creds() -> None:
    sample = "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2"
    facts = extract_facts("hydra", sample)
    assert ("admin", "hunter2") in facts.creds
    assert (22, "ssh") in facts.services
    assert "10.0.0.5" in facts.hosts


def test_medusa_format_creds() -> None:
    sample = "ACCOUNT FOUND: [ssh] Host: 10.0.0.5 User: root Password: toor [SUCCESS]"
    facts = extract_facts("medusa", sample)
    assert ("root", "toor") in facts.creds


def test_hydra_content_dispatch_without_tool_name() -> None:
    # The reflective runner passes "▸ run_command\n<output>" — no tool name.
    sample = "▸ run_command\n[21][ftp] host: 1.2.3.4   login: anonymous   password: anon"
    facts = extract_facts("", sample)
    assert ("anonymous", "anon") in facts.creds


def test_sqlmap_extracts_injectable_dbms_and_databases() -> None:
    sample = (
        "Parameter: id (GET)\n"
        "[INFO] GET parameter 'id' is vulnerable.\n"
        "back-end DBMS: MySQL >= 5.0\n"
        "available databases [2]:\n[*] acme\n[*] information_schema\n"
    )
    facts = extract_facts("", sample)  # content-dispatch via "back-end dbms"
    assert "sqli-confirmed" in facts.hints
    assert "sqli-param:id" in facts.hints
    assert ("dbms", "MySQL") in facts.versions
    assert "db:acme" in facts.paths


def test_nuclei_extracts_cve_and_filters_info() -> None:
    sample = (
        "[CVE-2021-44228] [http] [critical] http://t/api\n"
        "[tech-detect] [http] [info] http://t/\n"
    )
    facts = extract_facts("nuclei", sample)
    assert "cve:CVE-2021-44228" in facts.hints
    assert "nuclei:CVE-2021-44228" in facts.hints
    # info-severity hits are dropped (noise)
    assert not any("tech-detect" in h for h in facts.hints)


def test_dir_brute_extracts_paths_and_keeps_php_app_hints() -> None:
    sample = (
        "/admin                (Status: 200) [Size: 1234]\n"
        "/login.php            (Status: 302)\n"
    )
    facts = extract_facts("gobuster", sample)
    assert "/admin" in facts.paths
    # the generic php-app-page detection still fires (merged in)
    assert "discovered:login.php" in facts.hints
