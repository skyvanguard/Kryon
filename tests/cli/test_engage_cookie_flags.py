"""F202.U — HTTP cookie security flags detector tests.

Detecta cookies sin HttpOnly (CWE-1004), Secure (CWE-614), SameSite
(CWE-1275). Surfaced docker/vulnerable-lab smoke test: target-web
ground truth incluye "missing HttpOnly cookie" pero Kryon no lo
detectaba antes.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_http_cookie_flags


def _svc(port: int = 80, host: str = "10.0.0.1", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="http", product="")


def _fake_curl(headers: str):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=headers, stderr="")

    return _run


# ---------------------------------------------------------------------------
# HTTP — missing HttpOnly (the lab case)
# ---------------------------------------------------------------------------


class TestHttpOnlyMissing:
    def test_session_cookie_without_httponly_flags_medium(self):
        """Lab case: Set-Cookie PHPSESSID=abc; Path=/  (no HttpOnly)."""
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: PHPSESSID=abcdef123; Path=/\r\n"
            "Content-Type: text/html\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc())
        # MEDIUM HttpOnly + LOW SameSite (Secure not relevant on :80)
        rule_ids = [f.rule_id for f in findings]
        assert "http-cookie-missing-httponly" in rule_ids
        httponly = next(f for f in findings if f.rule_id == "http-cookie-missing-httponly")
        assert httponly.severity == "MEDIUM"
        assert httponly.cwe == "CWE-1004"
        assert "PHPSESSID" in httponly.message

    def test_cookie_with_httponly_no_flag(self):
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=xyz; Path=/; HttpOnly; SameSite=Lax\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "http-cookie-missing-httponly" not in rule_ids
        assert "http-cookie-missing-samesite" not in rule_ids

    def test_multiple_cookies_one_missing_httponly(self):
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: SESSION=secure1; HttpOnly; SameSite=Strict\r\n"
            "Set-Cookie: TRACKING=plain2; Path=/\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc())
        httponly = next(f for f in findings if f.rule_id == "http-cookie-missing-httponly")
        assert "TRACKING" in httponly.message
        assert "SESSION" not in httponly.message


# ---------------------------------------------------------------------------
# HTTPS — Secure flag check
# ---------------------------------------------------------------------------


class TestSecureFlag:
    def test_https_cookie_without_secure_flags_medium(self):
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=xyz; HttpOnly; SameSite=Lax\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc(port=443))
        rule_ids = [f.rule_id for f in findings]
        assert "http-cookie-missing-secure" in rule_ids
        secure = next(f for f in findings if f.rule_id == "http-cookie-missing-secure")
        assert secure.cwe == "CWE-614"
        assert secure.severity == "MEDIUM"

    def test_http_port_no_secure_check(self):
        """En HTTP plano :80, missing Secure NO es finding (no aplica)."""
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=xyz; HttpOnly; SameSite=Lax\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc(port=80))
        rule_ids = [f.rule_id for f in findings]
        assert "http-cookie-missing-secure" not in rule_ids

    def test_https_cookie_with_secure_ok(self):
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc(port=443))
        assert findings == []  # all flags present


# ---------------------------------------------------------------------------
# SameSite missing (LOW)
# ---------------------------------------------------------------------------


class TestSameSite:
    def test_missing_samesite_low(self):
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: csrf=token; HttpOnly\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "http-cookie-missing-samesite" in rule_ids
        samesite = next(f for f in findings if f.rule_id == "http-cookie-missing-samesite")
        assert samesite.cwe == "CWE-1275"
        assert samesite.severity == "LOW"


# ---------------------------------------------------------------------------
# Negative — no cookies, closed port, off-canonical
# ---------------------------------------------------------------------------


class TestNegative:
    def test_no_set_cookie_header_no_findings(self):
        headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc())
        assert findings == []

    def test_closed_port_skipped(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            findings = _check_http_cookie_flags(_svc(port=80, state="closed"))
        assert findings == []

    def test_non_http_port_skipped(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            findings = _check_http_cookie_flags(_svc(port=22))
        assert findings == []

    def test_curl_missing_graceful_skip(self):
        def _fnf(cmd, **_kw):
            raise FileNotFoundError("curl not installed")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_fnf):
            findings = _check_http_cookie_flags(_svc())
        assert findings == []

    def test_timeout_graceful_skip(self):
        def _timeout(cmd, **_kw):
            raise subprocess.TimeoutExpired(cmd, 8)

        with patch("kryon.cli.engage.subprocess.run", side_effect=_timeout):
            findings = _check_http_cookie_flags(_svc())
        assert findings == []


# ---------------------------------------------------------------------------
# Banking scenarios
# ---------------------------------------------------------------------------


class TestBankingScenarios:
    def test_https_session_cookie_missing_all_three_flags(self):
        """Worst case banking: HTTPS session cookie sin ningun flag."""
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: JSESSIONID=banking-session-id; Path=/\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http_cookie_flags(_svc(port=443))
        rule_ids = [f.rule_id for f in findings]
        # All 3: HttpOnly missing + Secure missing (HTTPS) + SameSite missing
        assert "http-cookie-missing-httponly" in rule_ids
        assert "http-cookie-missing-secure" in rule_ids
        assert "http-cookie-missing-samesite" in rule_ids
        assert len(findings) == 3
