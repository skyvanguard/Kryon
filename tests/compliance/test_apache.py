"""Apache HTTPD hardening — APACHE-1.1..2.2 (CIS Apache Benchmark subset).
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.apache.c_apache_1_1_server_tokens")
C12 = importlib.import_module("kryon.compliance.checks.apache.c_apache_1_2_server_signature")
C21 = importlib.import_module("kryon.compliance.checks.apache.c_apache_2_1_indexes")
C22 = importlib.import_module("kryon.compliance.checks.apache.c_apache_2_2_trace")

SPLIT = "---KRYON-SPLIT---"


def _out(present: str, matches: str, rc: int = 0):
    text = f"{present}\n{SPLIT}\n{matches}"

    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


_APACHE = "/etc/apache2"  # presence probe found a config dir
_NONE = ""  # no apache config dir


# --- 1.1 ServerTokens ---


def test_11_pass_prod(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_APACHE, "ServerTokens Prod"))
    assert C11.CHECK.run(CheckContext(host="web")).verdict == "PASS"


def test_11_fail_full(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_APACHE, "ServerTokens Full"))
    assert C11.CHECK.run(CheckContext(host="web")).verdict == "FAIL"


def test_11_fail_unset(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_APACHE, ""))
    assert C11.CHECK.run(CheckContext(host="web")).verdict == "FAIL"


def test_11_error_no_apache(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out(_NONE, ""))
    assert C11.CHECK.run(CheckContext(host="web")).verdict == "ERROR"


# --- 1.2 ServerSignature ---


def test_12_fail_on(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out(_APACHE, "ServerSignature On"))
    assert C12.CHECK.run(CheckContext(host="web")).verdict == "FAIL"


def test_12_pass_unset(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out(_APACHE, ""))
    assert C12.CHECK.run(CheckContext(host="web")).verdict == "PASS"


# --- 2.1 Options Indexes ---


def test_21_fail_indexes(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_APACHE, "Options Indexes FollowSymLinks"))
    assert C21.CHECK.run(CheckContext(host="web")).verdict == "FAIL"


def test_21_pass_minus_indexes(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_APACHE, "Options -Indexes +FollowSymLinks"))
    assert C21.CHECK.run(CheckContext(host="web")).verdict == "PASS"


def test_21_pass_none(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out(_APACHE, ""))
    assert C21.CHECK.run(CheckContext(host="web")).verdict == "PASS"


# --- 2.2 TraceEnable ---


def test_22_pass_off(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_APACHE, "TraceEnable Off"))
    assert C22.CHECK.run(CheckContext(host="web")).verdict == "PASS"


def test_22_fail_on(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_APACHE, "TraceEnable On"))
    assert C22.CHECK.run(CheckContext(host="web")).verdict == "FAIL"


def test_22_fail_unset(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out(_APACHE, ""))
    assert C22.CHECK.run(CheckContext(host="web")).verdict == "FAIL"


# --- registration + alias ---


def test_apache_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"APACHE-1.1", "APACHE-1.2", "APACHE-2.1", "APACHE-2.2"} <= ids
    for alias in ("apache", "httpd"):
        assert _FRAMEWORK_PREFIX[alias] == ("APACHE-",)
