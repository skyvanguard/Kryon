"""Microsoft Hyper-V hardening — HV-1.1..3.1 (CIS Hyper-V Benchmark subset).
run_cmd monkeypatched — no WinRM/host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_1_1_mac_spoofing")
C12 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_1_2_automatic_stop")
C21 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_2_1_secure_boot")
C22 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_2_2_guest_file_copy")
C31 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_3_1_migration_auth")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 MAC spoofing ---


def test_11_fail_spoofing_on(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("web01,db02\n"))
    r = C11.CHECK.run(CheckContext(host="hv"))
    assert r.verdict == "FAIL"
    assert "web01" in r.evidence_parsed["vms_with_mac_spoofing"]


def test_11_pass_none(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("\n"))
    assert C11.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


def test_11_error_not_hyperv(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="hv")).verdict == "ERROR"


# --- 1.2 automatic stop action ---


def test_12_fail_turnoff(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("legacy-vm\n"))
    assert C12.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_12_pass_save(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("\n"))
    assert C12.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


# --- 2.1 secure boot ---


def test_21_fail_secureboot_off(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("gen2vm\n"))
    assert C21.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_21_pass_all_on(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("\n"))
    assert C21.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


# --- 2.2 guest file copy ---


def test_22_fail_enabled(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("app01\n"))
    assert C22.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_22_pass_disabled(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("\n"))
    assert C22.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


# --- 3.1 migration auth ---


def test_31_fail_credssp(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out("CredSSP\n"))
    assert C31.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_31_pass_kerberos(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out("Kerberos\n"))
    assert C31.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


def test_31_error(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out("", 1))
    assert C31.CHECK.run(CheckContext(host="hv")).verdict == "ERROR"


# --- registration + framework alias ---


def test_hyperv_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"HV-1.1", "HV-1.2", "HV-2.1", "HV-2.2", "HV-3.1"} <= ids
    for alias in ("hyper-v", "hyperv"):
        assert _FRAMEWORK_PREFIX[alias] == ("HV-",)
