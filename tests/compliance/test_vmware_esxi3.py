"""VMware ESXi batch 3 — ESX-4.3 vSwitch, 6.2 VIB acceptance, 3.3 NTP firewall, 2.3 banner.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C43 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_4_3_vswitch_security")
C62 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_6_2_vib_acceptance")
C33 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_3_3_ntp_firewall")
C23 = importlib.import_module("kryon.compliance.checks.vmware.c_esx_2_3_login_banner")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 4.3 vSwitch security ---

_VSWITCH_LIST = "vSwitch0\n   Name: vSwitch0\n   Class: cswitch\n"
_POLICY_SECURE = "   Allow Promiscuous: false\n   Allow MAC Address Change: false\n   Allow Forged Transmits: false\n"
_POLICY_PROMISC = "   Allow Promiscuous: true\n   Allow MAC Address Change: false\n   Allow Forged Transmits: false\n"


def _vswitch(list_out: str, policy_out: str, list_rc: int = 0):
    def fake(_ctx, cmd, **_kw):
        if "policy security get" in cmd:
            return (policy_out, "", 0)
        if "list" in cmd:
            return (list_out, "", list_rc)
        return ("", "", 1)

    return fake


def test_43_pass_all_reject(monkeypatch):
    monkeypatch.setattr(C43, "run_cmd", _vswitch(_VSWITCH_LIST, _POLICY_SECURE))
    assert C43.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_43_fail_promiscuous(monkeypatch):
    monkeypatch.setattr(C43, "run_cmd", _vswitch(_VSWITCH_LIST, _POLICY_PROMISC))
    r = C43.CHECK.run(CheckContext(host="esx"))
    assert r.verdict == "FAIL"
    assert r.evidence_parsed["vswitches"]["vSwitch0"]["promiscuous"] is True


def test_43_na_no_vswitches(monkeypatch):
    monkeypatch.setattr(C43, "run_cmd", _vswitch("\n", _POLICY_SECURE))
    assert C43.CHECK.run(CheckContext(host="esx")).verdict == "N/A"


def test_43_error_list_fails(monkeypatch):
    monkeypatch.setattr(C43, "run_cmd", _vswitch("", _POLICY_SECURE, list_rc=1))
    assert C43.CHECK.run(CheckContext(host="esx")).verdict == "ERROR"


# --- 6.2 VIB acceptance ---


def test_62_pass_partner(monkeypatch):
    monkeypatch.setattr(C62, "run_cmd", _out("PartnerSupported\n"))
    assert C62.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_62_fail_community(monkeypatch):
    monkeypatch.setattr(C62, "run_cmd", _out("CommunitySupported\n"))
    assert C62.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 3.3 NTP firewall ruleset ---


def test_33_pass_enabled(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out("Name       Enabled\n---------  -------\nntpClient  true\n"))
    assert C33.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_33_fail_disabled(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out("Name       Enabled\n---------  -------\nntpClient  false\n"))
    assert C33.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- 2.3 login banner ---


def test_23_pass_banner_set(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("   String Value: Authorized use only. Monitored.\n"))
    assert C23.CHECK.run(CheckContext(host="esx")).verdict == "PASS"


def test_23_fail_empty(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("   String Value: \n"))
    assert C23.CHECK.run(CheckContext(host="esx")).verdict == "FAIL"


# --- registration ---


def test_batch3_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"ESX-2.3", "ESX-3.3", "ESX-4.3", "ESX-6.2"} <= ids
