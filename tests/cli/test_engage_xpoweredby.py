"""F199.L — X-Powered-By header info disclosure check.

Surfaced en POC piloto Example 2026-05-18 contra .115 (Evolution API
WhatsApp Business gateway en Node.js Express): el header
`X-Powered-By: Express` revela el framework y NO era detectado por
Kryon (solo `Server:` se inspeccionaba).
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_http


def _svc(host: str = "10.0.0.5", port: int = 8080) -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state="open", service="http", product="")


def _fake_curl(headers: str):
    """subprocess.run side_effect that returns the same headers for any
    curl call (both HEAD and any /admin probes use the same fake)."""

    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=headers, stderr="")

    return _run


# ---------------------------------------------------------------------------
# Positive cases — framework leaked
# ---------------------------------------------------------------------------


class TestXPoweredByLeakDetected:
    def test_express_node(self):
        """The exact case from .115 (Evolution API Node.js Express)."""
        headers = "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: application/json\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert len(xpb) == 1
        assert xpb[0].severity == "MEDIUM"
        assert xpb[0].cwe == "CWE-200"
        assert "Express" in xpb[0].evidence

    def test_php_with_version(self):
        headers = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1.10\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert len(xpb) == 1
        assert "PHP/8.1.10" in xpb[0].evidence

    def test_aspnet(self):
        headers = "HTTP/1.1 200 OK\r\nX-Powered-By: ASP.NET\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert len(xpb) == 1
        assert "ASP.NET" in xpb[0].evidence

    def test_servlet(self):
        headers = "HTTP/1.1 200 OK\r\nX-Powered-By: Servlet/4.0 JSP/2.3\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert len(xpb) == 1

    def test_case_insensitive_header_name(self):
        headers = "HTTP/1.1 200 OK\r\nx-powered-by: Express\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert len(xpb) == 1


# ---------------------------------------------------------------------------
# Negative cases — header absent or sanitized
# ---------------------------------------------------------------------------


class TestNoXPoweredByLeak:
    def test_header_absent_no_flag(self):
        headers = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert xpb == []

    def test_empty_response_no_flag(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl("")):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        assert xpb == []

    def test_only_server_header_no_xpb_flag(self):
        """Server header should still produce http-server-token finding,
        but no http-xpoweredby finding."""
        headers = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.62\r\n\r\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(headers)):
            findings = _check_http(_svc())
        xpb = [f for f in findings if f.rule_id == "http-xpoweredby"]
        st = [f for f in findings if f.rule_id == "http-server-token"]
        assert xpb == []
        assert len(st) == 1
