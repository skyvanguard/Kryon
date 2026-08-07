"""KVM / libvirt hardening batch 3 — 3.5 namespaces, 3.6 device ACL, 1.4 TLS key, 1.5 TLS verify.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C35 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_3_5_namespaces")
C36 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_3_6_device_acl")
C14 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_1_4_tls_key_perms")
C15 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_1_5_tls_verify")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 3.5 namespaces ---


def test_35_pass_mount(monkeypatch):
    monkeypatch.setattr(C35, "run_cmd", _out('namespaces = [ "mount" ]\n'))
    assert C35.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_35_fail_empty(monkeypatch):
    monkeypatch.setattr(C35, "run_cmd", _out("namespaces = [ ]\n"))
    assert C35.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_35_pass_default(monkeypatch):
    monkeypatch.setattr(C35, "run_cmd", _out('# namespaces = [ "mount" ]\nmax_processes = 0\n'))
    assert C35.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 3.6 device ACL ---


def test_36_pass_safe(monkeypatch):
    monkeypatch.setattr(C36, "run_cmd", _out('cgroup_device_acl = [\n  "/dev/null", "/dev/kvm", "/dev/urandom"\n]\n'))
    assert C36.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_36_fail_dangerous(monkeypatch):
    monkeypatch.setattr(C36, "run_cmd", _out('cgroup_device_acl = [\n  "/dev/null", "/dev/mem", "/dev/sda"\n]\n'))
    r = C36.CHECK.run(CheckContext(host="kvm"))
    assert r.verdict == "FAIL"
    assert "/dev/mem" in r.evidence_parsed["dangerous_devices"]


def test_36_pass_default(monkeypatch):
    monkeypatch.setattr(C36, "run_cmd", _out("# cgroup_device_acl = [ ... ]\nseccomp_sandbox = 1\n"))
    assert C36.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 1.4 TLS key perms ---


def test_14_pass_600_root(monkeypatch):
    monkeypatch.setattr(C14, "run_cmd", _out("600 root\n"))
    assert C14.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_14_fail_world_read(monkeypatch):
    monkeypatch.setattr(C14, "run_cmd", _out("644 root\n"))
    assert C14.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_14_fail_group_read(monkeypatch):
    monkeypatch.setattr(C14, "run_cmd", _out("640 root\n"))
    assert C14.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_14_na_no_key(monkeypatch):
    monkeypatch.setattr(C14, "run_cmd", _out("", 1))
    assert C14.CHECK.run(CheckContext(host="kvm")).verdict == "N/A"


# --- 1.5 TLS verify ---


def test_15_fail_no_verify(monkeypatch):
    monkeypatch.setattr(C15, "run_cmd", _out("tls_no_verify_certificate = 1\n"))
    assert C15.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_15_pass_verify(monkeypatch):
    monkeypatch.setattr(C15, "run_cmd", _out("tls_no_verify_certificate = 0\n"))
    assert C15.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_15_pass_default(monkeypatch):
    monkeypatch.setattr(C15, "run_cmd", _out("listen_tcp = 0\n"))
    assert C15.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- registration ---


def test_batch3_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"KVM-1.4", "KVM-1.5", "KVM-3.5", "KVM-3.6"} <= ids
