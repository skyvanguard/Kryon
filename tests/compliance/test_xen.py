"""Xen (XCP-ng / XenServer) hardening — XEN-1.1..2.2.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.xen.c_xen_1_1_ssh_keyonly")
C12 = importlib.import_module("kryon.compliance.checks.xen.c_xen_1_2_time_sync")
C13 = importlib.import_module("kryon.compliance.checks.xen.c_xen_1_3_remote_syslog")
C21 = importlib.import_module("kryon.compliance.checks.xen.c_xen_2_1_version")
C22 = importlib.import_module("kryon.compliance.checks.xen.c_xen_2_2_patches")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 SSH key-only ---


def test_11_pass_keyonly(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("passwordauthentication no\n"))
    assert C11.CHECK.run(CheckContext(host="xen")).verdict == "PASS"


def test_11_fail_password(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("passwordauthentication yes\n"))
    assert C11.CHECK.run(CheckContext(host="xen")).verdict == "FAIL"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="xen")).verdict == "ERROR"


# --- 1.2 time sync ---


def test_12_pass_synced(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("NTP=yes\nNTPSynchronized=yes\n"))
    assert C12.CHECK.run(CheckContext(host="xen")).verdict == "PASS"


def test_12_fail_not_synced(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("NTP=yes\nNTPSynchronized=no\n"))
    assert C12.CHECK.run(CheckContext(host="xen")).verdict == "FAIL"


def test_12_error(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("", 1))
    assert C12.CHECK.run(CheckContext(host="xen")).verdict == "ERROR"


# --- 1.3 remote syslog ---


def test_13_pass_dest(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("logging ( MRW): syslog_destination: siem.corp\n"))
    assert C13.CHECK.run(CheckContext(host="xen")).verdict == "PASS"


def test_13_fail_no_dest(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("logging ( MRW):\n"))
    assert C13.CHECK.run(CheckContext(host="xen")).verdict == "FAIL"


def test_13_error(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("", 1))
    assert C13.CHECK.run(CheckContext(host="xen")).verdict == "ERROR"


# --- 2.1 version ---


def test_21_pass_82(monkeypatch):
    monkeypatch.setattr(
        C21, "run_cmd", _out("software-version ( MRO): product_version: 8.2.1; product_brand: XCP-ng\n")
    )
    assert C21.CHECK.run(CheckContext(host="xen")).verdict == "PASS"


def test_21_fail_80_eol(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("software-version ( MRO): product_version: 8.0.0\n"))
    assert C21.CHECK.run(CheckContext(host="xen")).verdict == "FAIL"


def test_21_fail_7x_eol(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("software-version ( MRO): product_version: 7.6.0\n"))
    assert C21.CHECK.run(CheckContext(host="xen")).verdict == "FAIL"


def test_21_error(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("", 1))
    assert C21.CHECK.run(CheckContext(host="xen")).verdict == "ERROR"


# --- 2.2 patches ---


def test_22_pass_current(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("0\n"))
    assert C22.CHECK.run(CheckContext(host="xen")).verdict == "PASS"


def test_22_fail_pending(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("7\n"))
    assert C22.CHECK.run(CheckContext(host="xen")).verdict == "FAIL"


# --- registration + framework alias ---


def test_xen_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"XEN-1.1", "XEN-1.2", "XEN-1.3", "XEN-2.1", "XEN-2.2"} <= ids
    for alias in ("xen", "xcp-ng", "xenserver"):
        assert _FRAMEWORK_PREFIX[alias] == ("XEN-",)
