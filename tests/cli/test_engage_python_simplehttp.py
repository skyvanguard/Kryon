"""F199.J — `python -m http.server` directory listing detector.

Regression detectada en el POC piloto Example 2026-05-18 contra .200:
un Proxmox host con `python -m http.server 8888` sirviendo
`sgapp-temp-flat.vmdk` (disco virtual completo de VM) sin auth —
data exfiltration vector inmediato.

El check eleva la severidad a CRITICAL cuando el server header dice
SimpleHTTP/Python AND el body contiene `<title>Directory listing for ...`.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_python_simplehttp_exposed


def _svc(host: str = "10.0.0.5", port: int = 8888) -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state="open", service="http", product="")


def _fake_curl_pair(head: str, body: str):
    """subprocess.run side_effect that returns head for the -sSI call
    and body for the -sS call (matches the two curl invocations made
    inside _check_python_simplehttp_exposed)."""

    def _run(cmd, **_kw):
        if "-sSI" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=head, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

    return _run


# ---------------------------------------------------------------------------
# CRITICAL — server + directory listing
# ---------------------------------------------------------------------------


class TestCriticalDirectoryListing:
    def test_example_h200_scenario(self):
        """The exact case from .200 — VMDK exposed via python -m http.server."""
        head = (
            "HTTP/1.0 200 OK\r\n"
            "Server: SimpleHTTP/0.6 Python/3.11.2\r\n"
            "Date: Mon, 18 May 2026 21:35:14 GMT\r\n"
            "Content-type: text/html; charset=utf-8\r\n\r\n"
        )
        body = (
            "<!DOCTYPE HTML>\n<html>\n<head>\n<title>Directory listing for /</title>\n</head>\n"
            "<body>\n<h1>Directory listing for /</h1>\n<ul>\n"
            '<li><a href="sgapp-temp-flat.vmdk">sgapp-temp-flat.vmdk</a></li>\n'
            "</ul>\n</body></html>"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair(head, body)):
            finding = _check_python_simplehttp_exposed(_svc())
        assert finding is not None
        assert finding.severity == "CRITICAL"
        assert finding.cwe == "CWE-548"
        assert finding.rule_id == "python-simplehttp-directory-listing"
        # Evidence should include enough context for the operator to act.
        assert "Directory listing" in finding.evidence or "vmdk" in finding.evidence.lower()
        # Remediation must include the urgent stop command.
        assert "pkill" in finding.remediation or "stop" in finding.remediation.lower()

    def test_python_3_12_variant(self):
        head = "HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.12.0\r\n\r\n"
        body = "<title>Directory listing for /tmp/backup</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair(head, body)):
            finding = _check_python_simplehttp_exposed(_svc())
        assert finding is not None
        assert finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# HIGH — server but no directory listing (custom handler)
# ---------------------------------------------------------------------------


class TestHighCustomHandler:
    def test_simplehttp_without_dirlist_is_high(self):
        head = "HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.11.2\r\n\r\n"
        body = '{"status": "ok", "api": "custom"}'
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair(head, body)):
            finding = _check_python_simplehttp_exposed(_svc())
        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.rule_id == "python-simplehttp-exposed"


# ---------------------------------------------------------------------------
# Negative — must NOT flag
# ---------------------------------------------------------------------------


class TestNegative:
    def test_nginx_no_flag(self):
        head = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
        body = "<html>Welcome</html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair(head, body)):
            assert _check_python_simplehttp_exposed(_svc()) is None

    def test_apache_no_flag(self):
        head = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)\r\n\r\n"
        body = "<html>It works</html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair(head, body)):
            assert _check_python_simplehttp_exposed(_svc()) is None

    def test_curl_failure_no_flag(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair("", "")):
            assert _check_python_simplehttp_exposed(_svc()) is None

    def test_basehttpserver_uppercase_variant_still_caught(self):
        """`python3 -m http.server` and the older `BaseHTTPServer` both
        emit `SimpleHTTP/X.X Python/Y.Y`. Catch both."""
        head = "HTTP/1.0 200 OK\r\nserver: SimpleHTTP/0.6 Python/2.7.18\r\n\r\n"  # case-insensitive
        body = "<title>Directory listing for /</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_pair(head, body)):
            finding = _check_python_simplehttp_exposed(_svc())
        assert finding is not None
        assert finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# F199.K — Proxmox detect requires banner OR port 8006
# ---------------------------------------------------------------------------


class TestProxmoxBannerDetect:
    """The F199.K change refines Proxmox detection: port 3128 alone
    no longer triggers the family — banner confirmation is required.
    Validates against the Example .200 scenario (real Proxmox with
    banner pve-api-daemon on 3128) AND a hypothetical Squid host
    (port 3128, no Proxmox banner)."""

    def test_proxmox_real_banner_on_3128_detects(self):
        from kryon.cli.engage import _detect_device_families

        services = [
            DiscoveredService(host="h", port=3128, state="open", service="http", product="pve-api-daemon/3.0"),
        ]
        families = _detect_device_families(services)
        assert "proxmox" in families

    def test_squid_on_3128_no_proxmox(self):
        from kryon.cli.engage import _detect_device_families

        services = [
            DiscoveredService(host="h", port=3128, state="open", service="http-proxy", product="Squid http proxy 5.7"),
        ]
        families = _detect_device_families(services)
        assert "proxmox" not in families, f"Squid on 3128 must not be Proxmox: got {families}"

    def test_proxmox_canonical_port_8006_detects(self):
        from kryon.cli.engage import _detect_device_families

        services = [
            DiscoveredService(host="h", port=8006, state="open", service="https", product=""),
        ]
        families = _detect_device_families(services)
        assert "proxmox" in families
