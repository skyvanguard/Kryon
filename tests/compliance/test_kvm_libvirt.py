"""KVM / libvirt / QEMU hardening — KVM-1.1..3.2.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_1_1_libvirtd_tcp_auth")
C12 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_1_2_socket_perms")
C21 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_2_1_svirt")
C22 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_2_2_vnc_exposure")
C31 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_3_1_qemu_nonroot")
C32 = importlib.import_module("kryon.compliance.checks.kvm.c_kvm_3_2_image_perms")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 libvirtd TCP auth ---


def test_11_fail_unauth_tcp(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out('listen_tcp = 1\nauth_tcp = "none"\n'))
    assert C11.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_11_pass_tcp_off(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("listen_tcp = 0\n"))
    assert C11.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_11_pass_tcp_sasl(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out('listen_tcp = 1\nauth_tcp = "sasl"\n'))
    assert C11.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="kvm")).verdict == "ERROR"


# --- 1.2 socket perms ---


def test_12_fail_world_writable(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out('unix_sock_rw_perms = "0777"\n'))
    assert C12.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_12_pass_restricted(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out('unix_sock_group = "libvirt"\nunix_sock_rw_perms = "0770"\n'))
    assert C12.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 2.1 sVirt ---


def test_21_fail_none(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out('security_driver = "none"\n'))
    assert C21.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_21_pass_selinux(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out('security_driver = "selinux"\n'))
    assert C21.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_21_pass_default(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("# security_driver = ...\nmax_processes = 0\n"))
    assert C21.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 2.2 VNC exposure ---


def test_22_fail_exposed(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out('vnc_listen = "0.0.0.0"\n'))
    assert C22.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_22_pass_localhost(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out('vnc_listen = "127.0.0.1"\n'))
    assert C22.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_22_pass_tls(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out('vnc_listen = "0.0.0.0"\nvnc_tls = 1\n'))
    assert C22.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 3.1 QEMU non-root ---


def test_31_fail_root(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out('user = "root"\n'))
    assert C31.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_31_pass_qemu(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out('user = "qemu"\n'))
    assert C31.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


# --- 3.2 image perms ---


def test_32_fail_world_writable(monkeypatch):
    monkeypatch.setattr(C32, "run_cmd", _out("0777 root root\n"))
    assert C32.CHECK.run(CheckContext(host="kvm")).verdict == "FAIL"


def test_32_pass_restricted(monkeypatch):
    monkeypatch.setattr(C32, "run_cmd", _out("0750 root libvirt\n"))
    assert C32.CHECK.run(CheckContext(host="kvm")).verdict == "PASS"


def test_32_error_missing(monkeypatch):
    monkeypatch.setattr(C32, "run_cmd", _out("", 1))
    assert C32.CHECK.run(CheckContext(host="kvm")).verdict == "ERROR"


# --- registration + framework alias ---


def test_kvm_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"KVM-1.1", "KVM-1.2", "KVM-2.1", "KVM-2.2", "KVM-3.1", "KVM-3.2"} <= ids
    for alias in ("kvm", "libvirt", "qemu"):
        assert _FRAMEWORK_PREFIX[alias] == ("KVM-",)
