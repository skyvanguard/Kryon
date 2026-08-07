"""F6 — tests for the new exploit/lateral/privesc chain rules."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_cred_spray_smb,
    _rule_gtfobins_sudo_privesc,
    _rule_pth_lateral_with_nt_hash,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


# --- pass-the-hash lateral -------------------------------------------------


def test_pth_fires_on_nt_hash_and_domain():
    facts = ExtractedFacts(
        hashes=(f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{_NT}:::",),
        domains=("corp.local",),
        users=("Administrator",),
    )
    rec = _rule_pth_lateral_with_nt_hash(facts, [], "")
    assert rec is not None
    assert "crackmapexec smb" in rec.args
    assert f"-H {_NT}" in rec.args
    assert "corp.local" in rec.args


def test_pth_skips_krb5_hash():
    facts = ExtractedFacts(hashes=("$krb5asrep$23$user@DOMAIN:abcdef",), domains=("corp.local",))
    assert _rule_pth_lateral_with_nt_hash(facts, [], "") is None


def test_pth_needs_domain():
    facts = ExtractedFacts(hashes=("aabbccddeeff00112233445566778899",))
    assert _rule_pth_lateral_with_nt_hash(facts, [], "") is None


def test_pth_abstains_if_already_invoked():
    facts = ExtractedFacts(hashes=(_NT,), domains=("corp.local",))
    assert _rule_pth_lateral_with_nt_hash(facts, ["crackmapexec smb x -H y"], "") is None


# --- credential reuse over SMB ---------------------------------------------


def test_cred_spray_fires_on_creds_and_smb():
    facts = ExtractedFacts(creds=(("bob", "pass123"),), services=((445, "microsoft-ds"),))
    rec = _rule_cred_spray_smb(facts, [], "")
    assert rec is not None
    assert "crackmapexec smb" in rec.args and "bob" in rec.args


def test_cred_spray_needs_smb_or_domain():
    facts = ExtractedFacts(creds=(("bob", "pass"),), services=((22, "ssh"),))
    assert _rule_cred_spray_smb(facts, [], "") is None


def test_cred_spray_no_creds_no_fire():
    assert _rule_cred_spray_smb(ExtractedFacts(services=((445, "smb"),)), [], "") is None


# --- GTFOBins sudo privesc -------------------------------------------------


def test_gtfobins_known_binary_payload():
    facts = ExtractedFacts(hints=("(root) NOPASSWD: /usr/bin/find",))
    rec = _rule_gtfobins_sudo_privesc(facts, [], "")
    assert rec is not None
    assert "find" in rec.args and "/bin/sh" in rec.args


def test_gtfobins_generic_when_unknown_binary():
    facts = ExtractedFacts(hints=("(ALL) NOPASSWD: /opt/custom-tool",))
    rec = _rule_gtfobins_sudo_privesc(facts, [], "")
    assert rec is not None
    assert "gtfobins" in rec.args.lower()


def test_gtfobins_no_nopasswd_no_fire():
    assert _rule_gtfobins_sudo_privesc(ExtractedFacts(hints=("random",)), [], "") is None


def test_gtfobins_sudo_covers_zip_and_common_binaries():
    """Validating Tomghost (sudo zip NOPASSWD -> root) exposed that the GTFOBins map had only 11 binaries
    and missed zip + ~20 common ones, so the rule fell back to the generic 'check GTFOBins' message
    (conf 0.75) instead of the concrete payload. The expanded map must hand a real escalation (conf 0.9)
    for zip and the other common sudo-GTFOBins binaries."""
    from kryon.intelligence.exploit_chain_planner import _GTFOBINS_SUDO

    for binary in ("zip", "env", "ftp", "gdb", "node", "ruby", "php", "socat", "busybox", "docker", "sed", "make"):
        assert binary in _GTFOBINS_SUDO, f"{binary} missing from _GTFOBINS_SUDO"

    # zip is the Tomghost path — the rule must emit the concrete payload, not the 0.75 fallback.
    f = ExtractedFacts(hints=("(root : root) NOPASSWD: /usr/bin/zip",))
    rec = _rule_gtfobins_sudo_privesc(f, [], "privesc")
    assert rec is not None and rec.confidence == 0.9
    assert "zip" in rec.args and "sh #" in rec.args
