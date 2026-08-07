"""MikroTik RouterOS hardening — MTK-1.1..2.3.
run_cmd monkeypatched — no device access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.mikrotik.c_mtk_1_1_insecure_services")
C12 = importlib.import_module("kryon.compliance.checks.mikrotik.c_mtk_1_2_ssh_strong_crypto")
C13 = importlib.import_module("kryon.compliance.checks.mikrotik.c_mtk_1_3_bandwidth_server")
C21 = importlib.import_module("kryon.compliance.checks.mikrotik.c_mtk_2_1_ntp_client")
C22 = importlib.import_module("kryon.compliance.checks.mikrotik.c_mtk_2_2_snmp_community")
C23 = importlib.import_module("kryon.compliance.checks.mikrotik.c_mtk_2_3_remote_logging")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 insecure services ---

_SVC_INSECURE = "Flags: X - disabled\n #   NAME  PORT\n 2   www  80\n 3   ssh  22\n 5   winbox  8291\n"
_SVC_SECURE = "Flags: X - disabled\n #   NAME  PORT\n 3   ssh  22\n 5   winbox  8291\n"


def test_11_fail_www_enabled(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_SVC_INSECURE))
    r = C11.CHECK.run(CheckContext(host="mtk"))
    assert r.verdict == "FAIL"
    assert "www" in r.evidence_parsed["insecure_enabled"]


def test_11_pass_ssh_only(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_SVC_SECURE))
    assert C11.CHECK.run(CheckContext(host="mtk")).verdict == "PASS"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="mtk")).verdict == "ERROR"


# --- 1.2 SSH strong crypto ---


def test_12_fail_no(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("  forwarding-enabled: no\n  strong-crypto: no\n"))
    assert C12.CHECK.run(CheckContext(host="mtk")).verdict == "FAIL"


def test_12_pass_yes(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("  strong-crypto: yes\n"))
    assert C12.CHECK.run(CheckContext(host="mtk")).verdict == "PASS"


# --- 1.3 bandwidth server ---


def test_13_fail_enabled(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("  enabled: yes\n  authenticate: yes\n"))
    assert C13.CHECK.run(CheckContext(host="mtk")).verdict == "FAIL"


def test_13_pass_disabled(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("  enabled: no\n"))
    assert C13.CHECK.run(CheckContext(host="mtk")).verdict == "PASS"


# --- 2.1 NTP client ---


def test_21_pass_enabled(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("  enabled: yes\n  servers: pool.ntp.org\n"))
    assert C21.CHECK.run(CheckContext(host="mtk")).verdict == "PASS"


def test_21_fail_disabled(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("  enabled: no\n"))
    assert C21.CHECK.run(CheckContext(host="mtk")).verdict == "FAIL"


# --- 2.2 SNMP community ---


def test_22_fail_public(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("Flags: * - default\n #   NAME  ADDRESSES\n 0 * public  ::/0  none\n"))
    r = C22.CHECK.run(CheckContext(host="mtk"))
    assert r.verdict == "FAIL"
    assert "public" in r.evidence_parsed["default_communities"]


def test_22_pass_custom(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("Flags: * - default\n #   NAME  ADDRESSES\n 0   corpv3ro  10.0.0.0/8\n"))
    assert C22.CHECK.run(CheckContext(host="mtk")).verdict == "PASS"


# --- 2.3 remote logging ---


def test_23_pass_remote(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out(" #   NAME    TARGET  REMOTE\n 0   remote  remote  10.0.0.1\n"))
    assert C23.CHECK.run(CheckContext(host="mtk")).verdict == "PASS"


def test_23_fail_none(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out(" #   NAME  TARGET  REMOTE\n"))
    assert C23.CHECK.run(CheckContext(host="mtk")).verdict == "FAIL"


# --- registration + alias ---


def test_mtk_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"MTK-1.1", "MTK-1.2", "MTK-1.3", "MTK-2.1", "MTK-2.2", "MTK-2.3"} <= ids
    for alias in ("mikrotik", "routeros"):
        assert _FRAMEWORK_PREFIX[alias] == ("MTK-",)
