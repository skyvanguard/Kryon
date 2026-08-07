"""Microsoft IIS hardening — IIS-1.1..2.1 (CIS IIS Benchmark subset).
run_cmd monkeypatched — no WinRM/host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.iis.c_iis_1_1_directory_browse")
C12 = importlib.import_module("kryon.compliance.checks.iis.c_iis_1_2_detailed_errors")
C13 = importlib.import_module("kryon.compliance.checks.iis.c_iis_1_3_server_header")
C21 = importlib.import_module("kryon.compliance.checks.iis.c_iis_2_1_logging")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 directory browse ---


def test_11_fail_enabled(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("True\n"))
    assert C11.CHECK.run(CheckContext(host="iis")).verdict == "FAIL"


def test_11_pass_disabled(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("False\n"))
    assert C11.CHECK.run(CheckContext(host="iis")).verdict == "PASS"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="iis")).verdict == "ERROR"


# --- 1.2 detailed errors ---


def test_12_fail_detailed(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("Detailed\n"))
    assert C12.CHECK.run(CheckContext(host="iis")).verdict == "FAIL"


def test_12_pass_localonly(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("DetailedLocalOnly\n"))
    assert C12.CHECK.run(CheckContext(host="iis")).verdict == "PASS"


def test_12_pass_custom(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("Custom\n"))
    assert C12.CHECK.run(CheckContext(host="iis")).verdict == "PASS"


# --- 1.3 server header ---


def test_13_pass_true(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("True\n"))
    assert C13.CHECK.run(CheckContext(host="iis")).verdict == "PASS"


def test_13_fail_false(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("False\n"))
    assert C13.CHECK.run(CheckContext(host="iis")).verdict == "FAIL"


def test_13_na_old_iis(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("", 1))
    assert C13.CHECK.run(CheckContext(host="iis")).verdict == "N/A"


# --- 2.1 logging ---


def test_21_pass_enabled(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("True\n"))
    assert C21.CHECK.run(CheckContext(host="iis")).verdict == "PASS"


def test_21_fail_disabled(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("False\n"))
    assert C21.CHECK.run(CheckContext(host="iis")).verdict == "FAIL"


# --- registration + alias ---


def test_iis_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"IIS-1.1", "IIS-1.2", "IIS-1.3", "IIS-2.1"} <= ids
    assert _FRAMEWORK_PREFIX["iis"] == ("IIS-",)
