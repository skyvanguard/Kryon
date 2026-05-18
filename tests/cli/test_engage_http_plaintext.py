"""F199.G — _check_http no debe flag http-plaintext cuando hay redirect 301/302 a HTTPS.

Regression detectada en el POC piloto de Britimp 2026-05-18:
  - 172.18.201.117 (CentOS + nginx) → nginx hace `301 Moved Permanently`
    con `Location: https://...` en respuesta a HTTP plano.
  - Kryon flag-eaba HIGH "http-plaintext sin TLS" igualmente.
  - Resultado: ruido en el reporte (el host está bien configurado).

F199.G distingue tres estados:
  1. 301/302 a https:// → no flag (PASS — TLS enforcement).
  2. 2xx/4xx servido en HTTP plano → flag HIGH (real plaintext).
  3. Sin respuesta (curl falla / connect refused) → flag HIGH conservador.
"""

from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_http, _is_tls_redirect


def _svc(host: str, port: int) -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state="open", service="http", product="")


def _fake_curl(stdout: str):
    """Patch subprocess.run to return a CompletedProcess with stdout."""
    import subprocess

    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    return _run


# ---------------------------------------------------------------------------
# _is_tls_redirect — pure helper
# ---------------------------------------------------------------------------


class TestIsTlsRedirect:
    def test_301_to_https_is_true(self):
        h = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n"
        assert _is_tls_redirect(h) is True

    def test_302_to_https_is_true(self):
        h = "HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\n\r\n"
        assert _is_tls_redirect(h) is True

    def test_307_to_https_is_true(self):
        h = "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://x/\r\n\r\n"
        assert _is_tls_redirect(h) is True

    def test_308_to_https_is_true(self):
        h = "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://x/\r\n\r\n"
        assert _is_tls_redirect(h) is True

    def test_200_is_not_redirect(self):
        h = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        assert _is_tls_redirect(h) is False

    def test_301_to_http_only_is_not_tls_redirect(self):
        """301 to another http:// URL doesn't count as TLS enforcement."""
        h = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://x/other/\r\n\r\n"
        assert _is_tls_redirect(h) is False

    def test_no_location_is_not_redirect(self):
        h = "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n"
        assert _is_tls_redirect(h) is False

    def test_404_is_not_redirect(self):
        h = "HTTP/1.1 404 Not Found\r\nLocation: https://x/\r\n\r\n"
        assert _is_tls_redirect(h) is False

    def test_empty_headers_is_false(self):
        assert _is_tls_redirect("") is False

    def test_case_insensitive_location(self):
        h = "HTTP/1.1 301 Moved Permanently\r\nlocation: HTTPS://example.com/\r\n\r\n"
        assert _is_tls_redirect(h) is True


# ---------------------------------------------------------------------------
# _check_http end-to-end
# ---------------------------------------------------------------------------


class TestCheckHttpPlaintext:
    def test_redirect_301_to_https_does_not_flag_plaintext(self):
        svc = _svc("10.0.0.5", 80)
        headers = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Server: nginx\r\n"
            "Location: https://10.0.0.5/\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert plaintext == [], f"expected no http-plaintext finding, got {plaintext}"

    def test_redirect_302_to_https_does_not_flag_plaintext(self):
        svc = _svc("10.0.0.5", 80)
        headers = "HTTP/1.1 302 Found\r\nLocation: https://app.local/login\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert plaintext == []

    def test_plain_http_200_flags_high(self):
        svc = _svc("10.0.0.5", 80)
        headers = "HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\nContent-Type: text/html\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert len(plaintext) == 1
        assert plaintext[0].severity == "HIGH"

    def test_redirect_to_other_http_still_flags(self):
        """A 301 that bounces to another http:// URL is NOT TLS enforcement."""
        svc = _svc("10.0.0.5", 80)
        headers = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://other/\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert len(plaintext) == 1

    def test_curl_failure_still_flags(self):
        """If curl fails (no headers), keep the conservative HIGH flag —
        we can't verify TLS enforcement, so assume worst case."""
        svc = _svc("10.0.0.5", 80)
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl("")):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert len(plaintext) == 1
        assert plaintext[0].severity == "HIGH"

    def test_canonical_tls_port_443_never_flagged(self):
        svc = _svc("10.0.0.5", 443)
        headers = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert plaintext == []

    def test_port_8080_with_redirect_to_https(self):
        """8080 commonly used as HTTP alt — redirect should still PASS."""
        svc = _svc("10.0.0.5", 8080)
        headers = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://10.0.0.5:8443/\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(svc)
        plaintext = [f for f in findings if f.rule_id == "http-plaintext"]
        assert plaintext == []
