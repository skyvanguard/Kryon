"""nginx hardening — NGX-1.1..2.1 (CIS nginx Benchmark subset).
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.nginx.c_ngx_1_1_server_tokens")
C12 = importlib.import_module("kryon.compliance.checks.nginx.c_ngx_1_2_ssl_protocols")
C13 = importlib.import_module("kryon.compliance.checks.nginx.c_ngx_1_3_autoindex")
C21 = importlib.import_module("kryon.compliance.checks.nginx.c_ngx_2_1_worker_user")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 server_tokens ---


def test_11_pass_off(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("http {\n    server_tokens off;\n}\n"))
    assert C11.CHECK.run(CheckContext(host="ngx")).verdict == "PASS"


def test_11_fail_on(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("http {\n    server_tokens on;\n}\n"))
    assert C11.CHECK.run(CheckContext(host="ngx")).verdict == "FAIL"


def test_11_fail_unset(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("http {\n    sendfile on;\n}\n"))
    assert C11.CHECK.run(CheckContext(host="ngx")).verdict == "FAIL"


def test_11_ignores_comment(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("http {\n    # server_tokens on;\n    server_tokens off;\n}\n"))
    assert C11.CHECK.run(CheckContext(host="ngx")).verdict == "PASS"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="ngx")).verdict == "ERROR"


# --- 1.2 ssl_protocols ---


def test_12_pass_modern(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("server {\n    ssl_protocols TLSv1.2 TLSv1.3;\n}\n"))
    assert C12.CHECK.run(CheckContext(host="ngx")).verdict == "PASS"


def test_12_fail_tls10(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("server {\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n}\n"))
    r = C12.CHECK.run(CheckContext(host="ngx"))
    assert r.verdict == "FAIL"
    assert "tlsv1" in r.evidence_parsed["weak_protocols"]


def test_12_na_no_tls(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("http {\n    sendfile on;\n}\n"))
    assert C12.CHECK.run(CheckContext(host="ngx")).verdict == "N/A"


# --- 1.3 autoindex ---


def test_13_fail_on(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("location /files {\n    autoindex on;\n}\n"))
    assert C13.CHECK.run(CheckContext(host="ngx")).verdict == "FAIL"


def test_13_pass_absent(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("location / {\n    try_files $uri =404;\n}\n"))
    assert C13.CHECK.run(CheckContext(host="ngx")).verdict == "PASS"


# --- 2.1 worker user ---


def test_21_fail_root(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("user root;\nhttp {\n}\n"))
    assert C21.CHECK.run(CheckContext(host="ngx")).verdict == "FAIL"


def test_21_pass_nginx(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("user nginx;\nhttp {\n}\n"))
    assert C21.CHECK.run(CheckContext(host="ngx")).verdict == "PASS"


# --- registration + alias ---


def test_ngx_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"NGX-1.1", "NGX-1.2", "NGX-1.3", "NGX-2.1"} <= ids
    assert _FRAMEWORK_PREFIX["nginx"] == ("NGX-",)
