"""HAProxy hardening — HAP-1.1..2.1.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C11 = importlib.import_module("kryon.compliance.checks.haproxy.c_hap_1_1_weak_tls")
C12 = importlib.import_module("kryon.compliance.checks.haproxy.c_hap_1_2_stats_auth")
C13 = importlib.import_module("kryon.compliance.checks.haproxy.c_hap_1_3_logging")
C21 = importlib.import_module("kryon.compliance.checks.haproxy.c_hap_2_1_admin_socket")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.1 weak TLS ---


def test_11_pass_minver_12(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("global\n  ssl-default-bind-options ssl-min-ver TLSv1.2\n"))
    assert C11.CHECK.run(CheckContext(host="hap")).verdict == "PASS"


def test_11_fail_minver_10(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("global\n  ssl-default-bind-options ssl-min-ver TLSv1.0\n"))
    r = C11.CHECK.run(CheckContext(host="hap"))
    assert r.verdict == "FAIL"
    assert "tlsv1.0" in r.evidence_parsed["weak_ssl_min_ver"]


def test_11_pass_no_opts(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("global\n  ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11\n"))
    assert C11.CHECK.run(CheckContext(host="hap")).verdict == "PASS"


def test_11_na_no_policy(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("global\n  maxconn 2000\n"))
    assert C11.CHECK.run(CheckContext(host="hap")).verdict == "N/A"


def test_11_error(monkeypatch):
    monkeypatch.setattr(C11, "run_cmd", _out("", 1))
    assert C11.CHECK.run(CheckContext(host="hap")).verdict == "ERROR"


# --- 1.2 stats auth ---


def test_12_fail_no_auth(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("listen stats\n  stats enable\n  stats uri /stats\n"))
    assert C12.CHECK.run(CheckContext(host="hap")).verdict == "FAIL"


def test_12_pass_auth(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("listen stats\n  stats enable\n  stats auth admin:s3cret\n"))
    assert C12.CHECK.run(CheckContext(host="hap")).verdict == "PASS"


def test_12_na_no_stats(monkeypatch):
    monkeypatch.setattr(C12, "run_cmd", _out("frontend web\n  bind :80\n"))
    assert C12.CHECK.run(CheckContext(host="hap")).verdict == "N/A"


# --- 1.3 logging ---


def test_13_pass_log(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("global\n  log /dev/log local0\n"))
    assert C13.CHECK.run(CheckContext(host="hap")).verdict == "PASS"


def test_13_fail_no_log(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("global\n  maxconn 2000\n  log-tag haproxy\n"))
    assert C13.CHECK.run(CheckContext(host="hap")).verdict == "FAIL"


# --- 2.1 admin socket ---


def test_21_pass_unix(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("global\n  stats socket /run/haproxy/admin.sock mode 660 level admin\n"))
    assert C21.CHECK.run(CheckContext(host="hap")).verdict == "PASS"


def test_21_fail_tcp(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("global\n  stats socket ipv4@0.0.0.0:9999 level admin\n"))
    r = C21.CHECK.run(CheckContext(host="hap"))
    assert r.verdict == "FAIL"
    assert "ipv4@0.0.0.0:9999" in r.evidence_parsed["tcp_sockets"]


def test_21_na_no_socket(monkeypatch):
    monkeypatch.setattr(C21, "run_cmd", _out("global\n  maxconn 2000\n"))
    assert C21.CHECK.run(CheckContext(host="hap")).verdict == "N/A"


# --- registration + alias ---


def test_hap_registered_and_aliased():
    from kryon.compliance.runner import registered_checks
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    ids = {c.control_id for c in registered_checks()}
    assert {"HAP-1.1", "HAP-1.2", "HAP-1.3", "HAP-2.1"} <= ids
    assert _FRAMEWORK_PREFIX["haproxy"] == ("HAP-",)
