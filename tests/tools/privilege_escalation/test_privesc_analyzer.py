"""Deterministic privesc analyzer — CONFIRMED vs CANDIDATE vector classification."""

from __future__ import annotations

from kryon.tools.privilege_escalation.privesc_analyzer import analyze_privesc


def _rules(result, bucket="confirmed_vectors"):
    return {v["technique"] for v in result[bucket]}


def test_writable_etc_passwd_confirmed():
    r = analyze_privesc({"writable_files": ["/etc/passwd"]})
    assert "writable-etc-passwd" in _rules(r) and r["root_reachable"] is True


def test_suid_gtfobins_confirmed():
    r = analyze_privesc({"suid_binaries": ["/usr/bin/find", "/usr/bin/somecustombin"]})
    assert "suid-gtfobins" in _rules(r)
    # the custom (non-GTFOBins) binary doesn't produce a confirmed vector
    assert len([v for v in r["confirmed_vectors"] if v["technique"] == "suid-gtfobins"]) == 1


def test_suid_non_gtfobins_no_vector():
    r = analyze_privesc({"suid_binaries": ["/usr/bin/passwd", "/usr/bin/sudo"]})
    assert r["confirmed_vectors"] == []


def test_sudo_nopasswd_all_confirmed():
    r = analyze_privesc({"sudo_permissions": ["(ALL : ALL) NOPASSWD: ALL"]})
    assert "sudo-nopasswd-all" in _rules(r)


def test_sudo_nopasswd_gtfobins_confirmed():
    r = analyze_privesc({"sudo_permissions": ["(root) NOPASSWD: /usr/bin/find"]})
    assert "sudo-nopasswd-gtfobins" in _rules(r)


def test_sudo_nopasswd_safe_binary_no_vector():
    # a non-escapable binary under NOPASSWD shouldn't be flagged as confirmed root.
    r = analyze_privesc({"sudo_permissions": ["(root) NOPASSWD: /usr/sbin/service apache2 restart"]})
    assert "sudo-nopasswd-gtfobins" not in _rules(r)


def test_capability_setuid_confirmed():
    r = analyze_privesc({"capabilities": ["/usr/bin/python3 = cap_setuid+ep"]})
    assert "dangerous-capability" in _rules(r)


def test_cron_writable_root_confirmed():
    r = analyze_privesc({"cron_jobs": ["* * * * * root /opt/backup.sh (writable)"]})
    assert "cron-writable-root" in _rules(r)


def test_kernel_dirtypipe_candidate():
    r = analyze_privesc({"system_info": {"kernel": "5.10.0-generic"}})
    techs = _rules(r, "candidate_vectors")
    assert "kernel-exploit" in techs and r["root_reachable"] is False
    assert any("CVE-2022-0847" in v["evidence"] for v in r["candidate_vectors"])


def test_modern_kernel_no_candidate():
    r = analyze_privesc({"system_info": {"kernel": "6.5.0-generic"}})
    assert r["candidate_vectors"] == []


def test_empty_enum_clean():
    r = analyze_privesc({})
    assert r["confirmed_vectors"] == [] and r["candidate_vectors"] == [] and r["root_reachable"] is False


def test_dict_shaped_entries():
    # enum entries may be dicts, not strings.
    r = analyze_privesc({"suid_binaries": [{"path": "/usr/bin/nmap"}], "writable_files": [{"path": "/etc/shadow"}]})
    assert "suid-gtfobins" in _rules(r) and "writable-etc-passwd" in _rules(r)
