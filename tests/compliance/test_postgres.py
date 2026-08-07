"""PostgreSQL hardening — PG-1.1..2.2 (CIS PostgreSQL Benchmark subset).
run_cmd monkeypatched — no DB access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.postgres.c_pg_1_1_ssl")
C12 = importlib.import_module("kryon.compliance.checks.postgres.c_pg_1_2_log_connections")
C13 = importlib.import_module("kryon.compliance.checks.postgres.c_pg_1_3_log_disconnections")
C21 = importlib.import_module("kryon.compliance.checks.postgres.c_pg_2_1_password_encryption")
C22 = importlib.import_module("kryon.compliance.checks.postgres.c_pg_2_2_no_network_trust")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 SSL ---


def test_11_pass_on(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("on\n"))
    assert C11.CHECK.run(CheckContext(host="pg")).verdict == "PASS"


def test_11_fail_off(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("off\n"))
    assert C11.CHECK.run(CheckContext(host="pg")).verdict == "FAIL"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="pg")).verdict == "ERROR"


# --- 1.2 log_connections ---


def test_12_pass_on(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("on\n"))
    assert C12.CHECK.run(CheckContext(host="pg")).verdict == "PASS"


def test_12_fail_off(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("off\n"))
    assert C12.CHECK.run(CheckContext(host="pg")).verdict == "FAIL"


# --- 1.3 log_disconnections ---


def test_13_pass_on(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("on\n"))
    assert C13.CHECK.run(CheckContext(host="pg")).verdict == "PASS"


def test_13_fail_off(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("off\n"))
    assert C13.CHECK.run(CheckContext(host="pg")).verdict == "FAIL"


# --- 2.1 password_encryption ---


def test_21_pass_scram(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("scram-sha-256\n"))
    assert C21.CHECK.run(CheckContext(host="pg")).verdict == "PASS"


def test_21_fail_md5(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("md5\n"))
    assert C21.CHECK.run(CheckContext(host="pg")).verdict == "FAIL"


# --- 2.2 no network trust ---


def test_22_fail_host_trust(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("local|peer\nhost|scram-sha-256\nhost|trust\n"))
    r = C22.CHECK.run(CheckContext(host="pg"))
    assert r.verdict == "FAIL"
    assert r.evidence_parsed["network_trust_rules"] == 1


def test_22_pass_no_host_trust(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("local|trust\nhost|scram-sha-256\nhostssl|cert\n"))
    assert C22.CHECK.run(CheckContext(host="pg")).verdict == "PASS"


def test_22_error(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("", 1))
    assert C22.CHECK.run(CheckContext(host="pg")).verdict == "ERROR"


# --- registration + alias ---


def test_pg_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"PG-1.1", "PG-1.2", "PG-1.3", "PG-2.1", "PG-2.2"} <= ids
    for alias in ("postgresql", "postgres", "psql"):
        assert _FRAMEWORK_PREFIX[alias] == ("PG-",)
