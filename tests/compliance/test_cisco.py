"""Cisco IOS / IOS-XE hardening — IOS-1.1..2.2 (CIS Cisco Benchmark subset).
run_cmd monkeypatched — no device access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.cisco.c_ios_1_1_vty_ssh")
C12 = importlib.import_module("kryon.compliance.checks.cisco.c_ios_1_2_enable_secret")
C13 = importlib.import_module("kryon.compliance.checks.cisco.c_ios_1_3_password_encryption")
C21 = importlib.import_module("kryon.compliance.checks.cisco.c_ios_2_1_snmp_community")
C22 = importlib.import_module("kryon.compliance.checks.cisco.c_ios_2_2_http_server")

# Minimal fragment that passes looks_like_ios (has '!' and a common stanza).
_BASE = "version 15.2\n!\nhostname R1\n!\nline vty 0 4\n"


def _out(cfg: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (cfg, "", rc)

    return fake


# --- 1.1 VTY transport ---


def test_11_fail_telnet(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_BASE + " transport input telnet\n"))
    assert C11.CHECK.run(CheckContext(host="r1")).verdict == "FAIL"


def test_11_pass_ssh(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_BASE + " transport input ssh\n"))
    assert C11.CHECK.run(CheckContext(host="r1")).verdict == "PASS"


def test_11_error_not_ios(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("bash: show: command not found\n"))
    assert C11.CHECK.run(CheckContext(host="r1")).verdict == "ERROR"


# --- 1.2 enable secret ---


def test_12_fail_password_only(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out(_BASE + "enable password cisco123\n"))
    assert C12.CHECK.run(CheckContext(host="r1")).verdict == "FAIL"


def test_12_pass_secret(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out(_BASE + "enable secret 5 $1$abc\n"))
    assert C12.CHECK.run(CheckContext(host="r1")).verdict == "PASS"


# --- 1.3 service password-encryption ---


def test_13_pass_present(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out(_BASE + "service password-encryption\n"))
    assert C13.CHECK.run(CheckContext(host="r1")).verdict == "PASS"


def test_13_fail_absent(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out(_BASE + "service timestamps debug datetime\n"))
    assert C13.CHECK.run(CheckContext(host="r1")).verdict == "FAIL"


# --- 2.1 SNMP community ---


def test_21_fail_public(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_BASE + "snmp-server community public RO\n"))
    r = C21.CHECK.run(CheckContext(host="r1"))
    assert r.verdict == "FAIL"
    assert "public" in r.evidence_parsed["default_communities"]


def test_21_pass_custom(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_BASE + "snmp-server community S3cretRO RO\n"))
    assert C21.CHECK.run(CheckContext(host="r1")).verdict == "PASS"


# --- 2.2 HTTP server ---


def test_22_fail_enabled(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_BASE + "ip http server\n"))
    assert C22.CHECK.run(CheckContext(host="r1")).verdict == "FAIL"


def test_22_pass_disabled(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_BASE + "no ip http server\n"))
    assert C22.CHECK.run(CheckContext(host="r1")).verdict == "PASS"


# --- registration + alias ---


def test_ios_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"IOS-1.1", "IOS-1.2", "IOS-1.3", "IOS-2.1", "IOS-2.2"} <= ids
    for alias in ("cisco", "ios", "ios-xe"):
        assert _FRAMEWORK_PREFIX[alias] == ("IOS-",)
