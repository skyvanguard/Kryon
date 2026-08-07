"""Caddy hardening — CADDY-1.1..2.1.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.caddy.c_caddy_1_1_admin_exposure")
C12 = importlib.import_module("kryon.compliance.checks.caddy.c_caddy_1_2_auto_https")
C13 = importlib.import_module("kryon.compliance.checks.caddy.c_caddy_1_3_tls_protocols")
C21 = importlib.import_module("kryon.compliance.checks.caddy.c_caddy_2_1_file_browse")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 admin exposure ---


def test_11_fail_all_interfaces(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("{\n  admin 0.0.0.0:2019\n}\n"))
    assert C11.CHECK.run(CheckContext(host="caddy")).verdict == "FAIL"


def test_11_pass_localhost(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("{\n  admin localhost:2019\n}\n"))
    assert C11.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


def test_11_pass_default(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out('example.com {\n  respond "hi"\n}\n'))
    assert C11.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


def test_11_pass_off(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("{\n  admin off\n}\n"))
    assert C11.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="caddy")).verdict == "ERROR"


# --- 1.2 auto_https ---


def test_12_fail_off(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("{\n  auto_https off\n}\n"))
    assert C12.CHECK.run(CheckContext(host="caddy")).verdict == "FAIL"


def test_12_pass_default(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("example.com {\n  file_server\n}\n"))
    assert C12.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


def test_12_pass_disable_redirects(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("{\n  auto_https disable_redirects\n}\n"))
    assert C12.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


# --- 1.3 TLS protocols ---


def test_13_fail_tls10(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("example.com {\n  tls {\n    protocols tls1.0 tls1.3\n  }\n}\n"))
    r = C13.CHECK.run(CheckContext(host="caddy"))
    assert r.verdict == "FAIL"
    assert "tls1.0" in r.evidence_parsed["weak_protocols"]


def test_13_pass_modern(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("example.com {\n  tls {\n    protocols tls1.2 tls1.3\n  }\n}\n"))
    assert C13.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


def test_13_pass_default(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out('example.com {\n  respond "hi"\n}\n'))
    assert C13.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


# --- 2.1 file browse ---


def test_21_fail_browse_inline(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("example.com {\n  file_server browse\n}\n"))
    assert C21.CHECK.run(CheckContext(host="caddy")).verdict == "FAIL"


def test_21_fail_browse_block(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("example.com {\n  file_server {\n    browse\n  }\n}\n"))
    assert C21.CHECK.run(CheckContext(host="caddy")).verdict == "FAIL"


def test_21_pass_no_browse(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("example.com {\n  file_server\n}\n"))
    assert C21.CHECK.run(CheckContext(host="caddy")).verdict == "PASS"


# --- registration + alias ---


def test_caddy_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"CADDY-1.1", "CADDY-1.2", "CADDY-1.3", "CADDY-2.1"} <= ids
    assert _FRAMEWORK_PREFIX["caddy"] == ("CADDY-",)
