"""F200.B — Web server version EOL detection (nginx / Apache / IIS).

Surfaceado en POC piloto Example 2026-05-18 contra .18 (nginx 1.18.0
EOL desde abril 2023, vulnerable a CVE-2021-23017 CRITICAL pre-auth
RCE). El check generic http-server-token flag-eaba info disclosure
MEDIUM pero perdia la severidad real (la version disclosed era la
precondicion para RCE remoto).

F200.B parsea el Server header y eleva a HIGH CWE-1104 cuando la
version esta por debajo del minimo soportado, incluyendo el listado
de CVEs publicas aplicables en la remediation.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_webserver_eol


def _svc(port: int = 80) -> DiscoveredService:
    return DiscoveredService(host="10.0.0.5", port=port, state="open", service="http", product="")


def _headers(server_value: str) -> str:
    return f"HTTP/1.1 200 OK\r\nServer: {server_value}\r\nContent-Type: text/html\r\n\r\n"


# ---------------------------------------------------------------------------
# nginx — Example .18 regression
# ---------------------------------------------------------------------------


class TestNginxEol:
    def test_example_h18_nginx_1_18_0(self):
        """The exact case from .18 — nginx 1.18.0 Ubuntu LTS default."""
        headers = _headers("nginx/1.18.0 (Ubuntu)")
        f = _check_webserver_eol(_svc(), headers)
        assert f is not None
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-1104"
        assert f.rule_id == "nginx-version-eol"
        assert "1.18.0" in f.message
        # Remediation must cite the actual CVE-2021-23017 pre-auth RCE
        assert "CVE-2021-23017" in f.evidence
        # Upgrade path documented
        assert "1.26" in f.remediation

    def test_nginx_1_22_below_min(self):
        f = _check_webserver_eol(_svc(), _headers("nginx/1.22.1"))
        assert f is not None
        assert f.severity == "HIGH"

    def test_nginx_1_24_supported(self):
        """1.24 stable still below 1.26 LTS — flag HIGH."""
        f = _check_webserver_eol(_svc(), _headers("nginx/1.24.0"))
        assert f is not None
        assert f.severity == "HIGH"

    def test_nginx_1_26_passes(self):
        f = _check_webserver_eol(_svc(), _headers("nginx/1.26.0"))
        assert f is None

    def test_nginx_1_27_passes(self):
        """Mainline 1.27.x is more recent than 1.26 LTS — passes."""
        f = _check_webserver_eol(_svc(), _headers("nginx/1.27.5"))
        assert f is None

    def test_nginx_1_29_8_recent_passes(self):
        """The case from .119 (nginx ~Feb 2026) — must PASS."""
        f = _check_webserver_eol(_svc(), _headers("nginx/1.29.8"))
        assert f is None

    def test_nginx_without_version_no_flag(self):
        """nginx with no version (Server: nginx) — can't determine EOL."""
        f = _check_webserver_eol(_svc(), _headers("nginx"))
        assert f is None


# ---------------------------------------------------------------------------
# Apache
# ---------------------------------------------------------------------------


class TestApacheEol:
    def test_apache_2_4_52_below_min(self):
        f = _check_webserver_eol(_svc(), _headers("Apache/2.4.52 (Ubuntu)"))
        assert f is not None
        assert f.rule_id == "apache-httpd-version-eol"
        assert "CVE-2024-38476" in f.evidence

    def test_apache_2_4_60_minimum(self):
        """2.4.62 is min_supported. 2.4.60 below — flag."""
        f = _check_webserver_eol(_svc(), _headers("Apache/2.4.60"))
        assert f is not None

    def test_apache_2_4_62_passes(self):
        f = _check_webserver_eol(_svc(), _headers("Apache/2.4.62 (Debian)"))
        assert f is None

    def test_apache_2_4_64_recent_passes(self):
        f = _check_webserver_eol(_svc(), _headers("Apache/2.4.64"))
        assert f is None


# ---------------------------------------------------------------------------
# IIS
# ---------------------------------------------------------------------------


class TestIisEol:
    def test_iis_8_5_below_min(self):
        f = _check_webserver_eol(_svc(), _headers("Microsoft-IIS/8.5"))
        assert f is not None
        assert f.rule_id == "microsoft-iis-version-eol"
        # Remediation should hint at Win Server 2012 R2 EOL
        assert "2012" in f.remediation or "EOL" in f.remediation

    def test_iis_10_0_passes(self):
        f = _check_webserver_eol(_svc(), _headers("Microsoft-IIS/10.0"))
        assert f is None


# ---------------------------------------------------------------------------
# Negative — unknown server, no Server header, suppressed token
# ---------------------------------------------------------------------------


class TestNegative:
    def test_no_server_header_no_flag(self):
        headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        assert _check_webserver_eol(_svc(), headers) is None

    def test_unknown_server_no_flag(self):
        """Caddy, OpenLiteSpeed, Rocket — not in table → no flag."""
        f = _check_webserver_eol(_svc(), _headers("Caddy/2.7.6"))
        assert f is None
        f = _check_webserver_eol(_svc(), _headers("Rocket"))
        assert f is None

    def test_server_with_arbitrary_text_no_flag(self):
        """Server: foobar/3 — version present but unknown product."""
        assert _check_webserver_eol(_svc(), _headers("foobar/3.0.0")) is None
