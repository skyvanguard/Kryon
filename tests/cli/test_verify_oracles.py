"""Deterministic verification oracles — confirm SQLi/XSS/open-redirect, kill FPs."""

from __future__ import annotations

import urllib.parse

import kryon.cli.verify_oracles as vo

_URL = "http://t/item?id=1"


def _dec(url):
    return urllib.parse.unquote_plus(url)


def test_sqli_error_based():
    def req(url):
        u = _dec(url)
        body = "Microsoft OLE DB Provider error '80040e14' Unclosed quotation mark" if "'" in u else "normal page"
        return (200, {}, body, 0.1)
    v = vo.verify_sqli(_URL, "id", request=req)
    assert v.confirmed and v.technique == "sqli-error"


def test_sqli_boolean_based():
    def req(url):
        u = _dec(url)
        if "'1'='1" in u:
            return (200, {}, "X" * 1000, 0.1)  # true ~ baseline
        if "'1'='2" in u:
            return (200, {}, "X" * 100, 0.1)   # false diverges
        return (200, {}, "X" * 1000, 0.1)      # baseline
    v = vo.verify_sqli(_URL, "id", request=req)
    assert v.confirmed and v.technique == "sqli-boolean"


def test_sqli_time_based():
    def req(url):
        if "SLEEP" in url:
            return (200, {}, "ok", 5.2)
        return (200, {}, "ok", 0.1)
    v = vo.verify_sqli(_URL, "id", request=req)
    assert v.confirmed and v.technique == "sqli-time"


def test_sqli_clean_not_confirmed():
    def req(url):
        return (200, {}, "same stable page content here", 0.1)
    assert vo.verify_sqli(_URL, "id", request=req).confirmed is False


def test_xss_reflected_unescaped():
    def req(url):
        return (200, {}, "<html>echo: kx9z\"><svg/onload=alert(1337)> done</html>", 0.1)
    v = vo.verify_xss(_URL, "q", request=req)
    assert v.confirmed and v.technique == "xss-reflected"


def test_xss_escaped_not_confirmed():
    def req(url):
        return (200, {}, "echo: kx9z&quot;&gt;&lt;svg/onload=alert(1337)&gt;", 0.1)
    assert vo.verify_xss(_URL, "q", request=req).confirmed is False


def test_open_redirect_confirmed():
    def req(url):
        return (302, {"location": "https://kryon-canary.example/x"}, "", 0.1)
    v = vo.verify_open_redirect(_URL, "next", request=req)
    assert v.confirmed and v.technique == "open-redirect"


def test_open_redirect_safe_not_confirmed():
    def req(url):
        return (302, {"location": "/dashboard"}, "", 0.1)
    assert vo.verify_open_redirect(_URL, "next", request=req).confirmed is False


def test_to_finding_only_on_confirmed():
    assert vo.to_finding(vo.OracleVerdict(False, "sqli", "x"), _URL, "id", "t") is None
    f = vo.to_finding(vo.OracleVerdict(True, "sqli-error", "DB error"), _URL, "id", "10.0.0.1")
    assert f is not None and f.cwe == "CWE-89" and f.severity == "CRITICAL" and f.rule_id == "verified-sqli-error"


def test_run_verification_gated(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert vo.run_verification(_URL, "id", "t") == []  # active → gated off by default


def test_with_param_replaces_query():
    out = vo._with_param("http://t/p?id=1&x=2", "id", "9' OR 1=1")
    assert "id=9" in out and "x=2" in out
