"""Linux OS baseline — LNX-1.1..2.3 (CIS Distribution-Independent Linux subset).
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.linux.c_lnx_1_1_root_login")
C12 = importlib.import_module("kryon.compliance.checks.linux.c_lnx_1_2_empty_passwords_ssh")
C21 = importlib.import_module("kryon.compliance.checks.linux.c_lnx_2_1_shadow_empty_password")
C22 = importlib.import_module("kryon.compliance.checks.linux.c_lnx_2_2_uid0")
C23 = importlib.import_module("kryon.compliance.checks.linux.c_lnx_2_3_shadow_perms")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 PermitRootLogin ---


def test_11_fail_yes(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("permitrootlogin yes\n"))
    assert C11.CHECK.run(CheckContext(host="lnx")).verdict == "FAIL"


def test_11_pass_prohibit(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("permitrootlogin prohibit-password\n"))
    assert C11.CHECK.run(CheckContext(host="lnx")).verdict == "PASS"


def test_11_pass_no(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("permitrootlogin no\n"))
    assert C11.CHECK.run(CheckContext(host="lnx")).verdict == "PASS"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 0))
    assert C11.CHECK.run(CheckContext(host="lnx")).verdict == "ERROR"


# --- 1.2 PermitEmptyPasswords ---


def test_12_fail_yes(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("permitemptypasswords yes\n"))
    assert C12.CHECK.run(CheckContext(host="lnx")).verdict == "FAIL"


def test_12_pass_no(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("permitemptypasswords no\n"))
    assert C12.CHECK.run(CheckContext(host="lnx")).verdict == "PASS"


# --- 2.1 shadow empty password ---


def test_21_fail_empty(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("games\nbackup\n"))
    r = C21.CHECK.run(CheckContext(host="lnx"))
    assert r.verdict == "FAIL"
    assert "games" in r.evidence_parsed["empty_password_accounts"]


def test_21_pass_none(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("", 0))
    assert C21.CHECK.run(CheckContext(host="lnx")).verdict == "PASS"


def test_21_error_noread(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("__KRYON_NOREAD__\n"))
    assert C21.CHECK.run(CheckContext(host="lnx")).verdict == "ERROR"


# --- 2.2 UID 0 ---


def test_22_pass_root_only(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("root\n"))
    assert C22.CHECK.run(CheckContext(host="lnx")).verdict == "PASS"


def test_22_fail_extra(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("root\ntoor\n"))
    r = C22.CHECK.run(CheckContext(host="lnx"))
    assert r.verdict == "FAIL"
    assert "toor" in r.evidence_parsed["extra_uid0_accounts"]


def test_22_error(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("", 1))
    assert C22.CHECK.run(CheckContext(host="lnx")).verdict == "ERROR"


# --- 2.3 shadow perms ---


def test_23_pass_640(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("640\n"))
    assert C23.CHECK.run(CheckContext(host="lnx")).verdict == "PASS"


def test_23_fail_644(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("644\n"))
    assert C23.CHECK.run(CheckContext(host="lnx")).verdict == "FAIL"


def test_23_error(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("", 1))
    assert C23.CHECK.run(CheckContext(host="lnx")).verdict == "ERROR"


# --- registration + alias ---


def test_lnx_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"LNX-1.1", "LNX-1.2", "LNX-2.1", "LNX-2.2", "LNX-2.3"} <= ids
    for alias in ("linux", "cis-linux"):
        assert _FRAMEWORK_PREFIX[alias] == ("LNX-",)
