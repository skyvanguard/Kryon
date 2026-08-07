"""KVM / libvirt hardening batch 2 — 2.3 SPICE, 3.3 seccomp, 3.4 caps, 1.3 audit.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C23 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_2_3_spice_exposure")
C33 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_3_3_seccomp")
C34 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_3_4_clear_capabilities")
C13 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_1_3_audit_logging")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 2.3 SPICE exposure ---


def test_23_fail_exposed(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out('spice_listen = "0.0.0.0"\n'))
    assert C23.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_23_pass_localhost(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out('spice_listen = "127.0.0.1"\n'))
    assert C23.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_23_pass_tls(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out('spice_listen = "0.0.0.0"\nspice_tls = 1\n'))
    assert C23.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_23_error(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("", 1))
    assert C23.CHECK.run(CheckContext(host="kvm")).verdict == "ERROR"


# --- 3.3 seccomp ---


def test_33_fail_disabled(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out("seccomp_sandbox = 0\n"))
    assert C33.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_33_pass_enabled(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out("seccomp_sandbox = 1\n"))
    assert C33.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_33_pass_default(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out("# seccomp_sandbox = 1\nmax_processes = 0\n"))
    assert C33.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 3.4 clear capabilities ---


def test_34_fail_disabled(monkeypatch):
    monkeypatch.setattr(C34, "run_cmd", _out("clear_emulator_capabilities = 0\n"))
    assert C34.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_34_pass_enabled(monkeypatch):
    monkeypatch.setattr(C34, "run_cmd", _out("clear_emulator_capabilities = 1\n"))
    assert C34.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 1.3 audit logging ---


def test_13_fail_disabled(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("audit_level = 0\n"))
    assert C13.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_13_pass_enabled(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("audit_level = 1\n"))
    assert C13.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_13_pass_default(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("# audit_level = 1\nlisten_tcp = 0\n"))
    assert C13.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- registration ---


def test_batch2_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"KVM-1.3", "KVM-2.3", "KVM-3.3", "KVM-3.4"} <= ids
