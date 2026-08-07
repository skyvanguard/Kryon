"""VMware ESXi (CIS ESXi Benchmark subset) — ESX-1.1..6.1.
run_cmd monkeypatched — no host access, no SSH."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_1_1_shell_timeout")
C12 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_1_2_mob_disabled")
C21 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_2_1_account_lockout")
C31 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_3_1_ntp")
C32 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_3_2_remote_syslog")
C41 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_4_1_firewall")
C61 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_6_1_weak_tls")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


def _adv_int(value):
    return f"   Path: /x\n   Type: integer\n   Int Value: {value}\n   Default Int Value: 0\n"


# --- 1.1 shell timeout ---


def test_11_pass_timeout_set(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_adv_int(900)))
    assert C11.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_11_fail_no_timeout(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_adv_int(0)))
    assert C11.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


def test_11_error_unreadable(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="esx")).verdict == "ERROR"


# --- 1.2 MOB ---


def test_12_pass_mob_off(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out(_adv_int(0)))
    assert C12.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_12_fail_mob_on(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out(_adv_int(1)))
    assert C12.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 2.1 account lockout ---


def test_21_pass_lockout(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_adv_int(3)))
    assert C21.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_21_fail_no_lockout(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_adv_int(0)))
    assert C21.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 3.1 NTP ---


def test_31_pass_ntp(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out("   Enabled: true\n   Servers: [pool.ntp.org]\n"))
    assert C31.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_31_fail_ntp_off(monkeypatch):
    monkeypatch.setattr(C31, "run_cmd", _out("   Enabled: false\n   Servers: []\n"))
    assert C31.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 3.2 remote syslog ---


def test_32_pass_loghost(monkeypatch):
    monkeypatch.setattr(
        C32, "run_cmd", _out("   Remote Host: tcp://siem.corp:514\n   Local Log Output: /scratch/log\n")
    )
    assert C32.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_32_fail_no_loghost(monkeypatch):
    monkeypatch.setattr(C32, "run_cmd", _out("   Remote Host: <none>\n"))
    assert C32.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 4.1 firewall ---


def test_41_pass_deny(monkeypatch):
    monkeypatch.setattr(C41, "run_cmd", _out("   Default Action: DROP\n   Enabled: true\n   Loaded: true\n"))
    assert C41.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_41_fail_default_pass(monkeypatch):
    monkeypatch.setattr(C41, "run_cmd", _out("   Default Action: PASS\n   Enabled: true\n"))
    assert C41.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 6.1 weak TLS ---


def test_61_pass_weak_disabled(monkeypatch):
    monkeypatch.setattr(C61, "run_cmd", _out("   String Value: sslv3,tlsv1,tlsv1.1\n"))
    assert C61.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_61_fail_tls10_enabled(monkeypatch):
    monkeypatch.setattr(C61, "run_cmd", _out("   String Value: sslv3\n"))
    r = C61.CHECK.run(CheckContext(host="esx"))
    assert r.verdict == "FAIL"
    assert "tlsv1" in r.evidence_parsed["still_enabled"]


# --- registration ---


def test_esxi_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"ESX-1.1", "ESX-1.2", "ESX-2.1", "ESX-3.1", "ESX-3.2", "ESX-4.1", "ESX-6.1"} <= ids
