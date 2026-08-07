"""VMware ESXi batch 2 — ESX-1.3/1.4 timeouts, 2.2 unlock, 4.2 SNMP, 5.1/5.2 passwords.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C13 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_1_3_dcui_timeout")
C14 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_1_4_shell_service_timeout")
C22 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_2_2_account_unlock_time")
C42 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_4_2_snmp")
C51 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_5_1_password_complexity")
C52 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_5_2_password_history")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


def _adv_int(value):
    return f"   Path: /x\n   Type: integer\n   Int Value: {value}\n   Default Int Value: 0\n"


def _adv_str(value):
    return f"   Path: /x\n   Type: string\n   String Value: {value}\n"


# --- 1.3 DCUI timeout ---


def test_13_pass(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out(_adv_int(600)))
    assert C13.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_13_fail_zero(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out(_adv_int(0)))
    assert C13.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


def test_13_error(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("", 1))
    assert C13.CHECK.run(CheckContext(host="esx")).verdict == "ERROR"


# --- 1.4 shell service timeout ---


def test_14_pass(monkeypatch):
    monkeypatch.setattr(C14, "run_cmd", _out(_adv_int(3600)))
    assert C14.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_14_fail_zero(monkeypatch):
    monkeypatch.setattr(C14, "run_cmd", _out(_adv_int(0)))
    assert C14.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 2.2 account unlock time ---


def test_22_pass(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_adv_int(900)))
    assert C22.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_22_fail_zero(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_adv_int(0)))
    assert C22.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 4.2 SNMP ---


def test_42_pass_disabled(monkeypatch):
    monkeypatch.setattr(C42, "run_cmd", _out("   Communities:\n   Enable: false\n   Users:\n"))
    assert C42.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_42_fail_v2c_community(monkeypatch):
    monkeypatch.setattr(C42, "run_cmd", _out("   Communities: public\n   Enable: true\n   Users:\n"))
    r = C42.CHECK.run(CheckContext(host="esx"))
    assert r.verdict == "FAIL"
    assert r.evidence_parsed["has_v1v2c_community"] is True


# --- 5.1 password complexity ---


def test_51_pass_min7(monkeypatch):
    monkeypatch.setattr(C51, "run_cmd", _out(_adv_str("retry=3 min=disabled,disabled,disabled,7,7")))
    assert C51.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_51_fail_min5(monkeypatch):
    monkeypatch.setattr(C51, "run_cmd", _out(_adv_str("retry=3 min=disabled,disabled,disabled,5,5")))
    assert C51.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


def test_51_fail_unset(monkeypatch):
    monkeypatch.setattr(C51, "run_cmd", _out(_adv_str("")))
    assert C51.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 5.2 password history ---


def test_52_pass(monkeypatch):
    monkeypatch.setattr(C52, "run_cmd", _out(_adv_int(5)))
    assert C52.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_52_fail_zero(monkeypatch):
    monkeypatch.setattr(C52, "run_cmd", _out(_adv_int(0)))
    assert C52.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- registration ---


def test_batch2_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"ESX-1.3", "ESX-1.4", "ESX-2.2", "ESX-4.2", "ESX-5.1", "ESX-5.2"} <= ids
