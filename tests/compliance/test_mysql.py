"""MySQL / MariaDB hardening — MYSQL-1.1..2.3 (CIS MySQL Benchmark subset).
run_cmd monkeypatched — no DB access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.mysql.c_mysql_1_1_require_tls")
C12 = importlib.import_module("kryon.compliance.checks.mysql.c_mysql_1_2_local_infile")
C21 = importlib.import_module("kryon.compliance.checks.mysql.c_mysql_2_1_anonymous_users")
C22 = importlib.import_module("kryon.compliance.checks.mysql.c_mysql_2_2_root_any_host")
C23 = importlib.import_module("kryon.compliance.checks.mysql.c_mysql_2_3_test_database")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 require TLS ---


def test_11_pass_on(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("1\n"))
    assert C11.CHECK.run(CheckContext(host="db")).verdict == "PASS"


def test_11_fail_off(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("0\n"))
    assert C11.CHECK.run(CheckContext(host="db")).verdict == "FAIL"


def test_11_na_absent(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="db")).verdict == "N/A"


# --- 1.2 local_infile ---


def test_12_fail_on(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("1\n"))
    assert C12.CHECK.run(CheckContext(host="db")).verdict == "FAIL"


def test_12_pass_off(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("0\n"))
    assert C12.CHECK.run(CheckContext(host="db")).verdict == "PASS"


def test_12_error(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("", 1))
    assert C12.CHECK.run(CheckContext(host="db")).verdict == "ERROR"


# --- 2.1 anonymous users ---


def test_21_fail_anon(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("2\n"))
    assert C21.CHECK.run(CheckContext(host="db")).verdict == "FAIL"


def test_21_pass_none(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("0\n"))
    assert C21.CHECK.run(CheckContext(host="db")).verdict == "PASS"


def test_21_error(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("", 1))
    assert C21.CHECK.run(CheckContext(host="db")).verdict == "ERROR"


# --- 2.2 root any host ---


def test_22_fail_root_wildcard(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("1\n"))
    assert C22.CHECK.run(CheckContext(host="db")).verdict == "FAIL"


def test_22_pass_localhost_only(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("0\n"))
    assert C22.CHECK.run(CheckContext(host="db")).verdict == "PASS"


# --- 2.3 test database ---


def test_23_fail_present(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("1\n"))
    assert C23.CHECK.run(CheckContext(host="db")).verdict == "FAIL"


def test_23_pass_absent(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("0\n"))
    assert C23.CHECK.run(CheckContext(host="db")).verdict == "PASS"


# --- registration + alias ---


def test_mysql_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"MYSQL-1.1", "MYSQL-1.2", "MYSQL-2.1", "MYSQL-2.2", "MYSQL-2.3"} <= ids
    for alias in ("mysql", "mariadb"):
        assert _FRAMEWORK_PREFIX[alias] == ("MYSQL-",)
