"""fact_extractor must surface Linux privesc primitives from generic output.

Regression: `run_command` (the privesc workhorse) matches no _DISPATCH entry and
fell to _parse_generic, which had no privesc parsers — so `sudo -l` NOPASSWD, SUID
binaries, capabilities, shadow hashes and SSH keys never became durable facts and
the privesc rules never fired."""

from __future__ import annotations

from kryon.intelligence.fact_extractor import extract_facts


def test_sudo_nopasswd_becomes_privesc_hint():
    out = "Matching Defaults entries:\n\nUser bob may run:\n    (ALL) NOPASSWD: /usr/bin/find\n"
    facts = extract_facts("run_command", out)
    assert any(h.startswith("privesc:sudo-nopasswd:") and "/usr/bin/find" in h for h in facts.hints)


def test_suid_binary_becomes_privesc_hint():
    out = "-rwsr-xr-x 1 root root 40000 Jan 1 /usr/bin/pkexec\n-rw-r--r-- 1 root root 10 /etc/x\n"
    facts = extract_facts("run_command", out)
    assert any(h == "privesc:suid:/usr/bin/pkexec" for h in facts.hints)


def test_capability_becomes_privesc_hint():
    out = "/usr/bin/python3.8 = cap_setuid+ep\n"
    facts = extract_facts("run_command", out)
    assert any(h.startswith("privesc:cap:/usr/bin/python3.8") for h in facts.hints)


def test_shadow_hash_is_extracted():
    out = "root:$6$abcd$eFgHiJkLmNoP0123456789:19000:0:99999:7:::\ndaemon:*:19000:0::::\n"
    facts = extract_facts("run_command", out)
    assert any("$6$abcd$" in h for h in facts.hashes)


def test_ssh_private_key_becomes_hint():
    out = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n-----END OPENSSH PRIVATE KEY-----\n"
    facts = extract_facts("run_command", out)
    assert "privesc:ssh-private-key" in facts.hints


def test_benign_output_produces_no_privesc_noise():
    out = "total 4\ndrwxr-xr-x 2 user user 4096 Jan 1 documents\n"
    facts = extract_facts("run_command", out)
    assert not any(h.startswith("privesc:") for h in facts.hints)
