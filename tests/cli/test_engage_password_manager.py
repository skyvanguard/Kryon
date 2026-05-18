"""F199.N — Self-hosted password manager detection.

Regresion detectada en POC piloto Britimp 2026-05-18 contra .99:
Vaultwarden corporativo (gestor de credenciales) accesible desde
el segmento de servidores generales, con certificado autofirmado
y sin que Kryon resalte la criticidad del asset.

El detector flag-ea HIGH (CWE-668 Exposure to Wrong Sphere) cuando
el body del root contiene marcadores conocidos de:
  - Vaultwarden / Bitwarden self-hosted
  - Passbolt
  - Padloc
  - KeeWeb (KeePass web)
  - Pleasant Password Server
  - Psono
  - Teampass
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_password_manager


def _svc(host: str = "10.0.0.5", port: int = 443) -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state="open", service="https", product="")


def _fake_curl(body: str, code: int = 200):
    """subprocess.run side_effect that returns the body + an HTTPCODE marker
    (matches the format _http_get parses)."""

    def _run(cmd, **_kw):
        stdout = f"{body}\n__HTTPCODE__{code}"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    return _run


# ---------------------------------------------------------------------------
# Vaultwarden — the exact case from .99
# ---------------------------------------------------------------------------


class TestVaultwardenDetection:
    def test_britimp_h99_scenario(self):
        body = (
            '<!doctype html><html class="theme_light"><head>'
            '<meta charset="utf-8"/>'
            "<title page-title>Vaultwarden Web</title>"
            "</head><body></body></html>"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-668"
        assert finding.rule_id == "password-manager-vaultwarden"
        assert "Vaultwarden" in finding.message
        # Remediation must mention MFA + segmentation review
        assert "MFA" in finding.remediation or "TOTP" in finding.remediation
        assert "segment" in finding.remediation.lower()


class TestBitwardenSelfHosted:
    def test_bitwarden_official(self):
        body = "<html><head><title>Bitwarden Login</title></head></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-bitwarden"


class TestOtherPasswordManagers:
    def test_passbolt(self):
        body = "<html><head><title>Passbolt | Password Manager</title></head></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-passbolt"

    def test_padloc(self):
        body = "<html><body>Welcome to padloc-app</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-padloc"

    def test_keeweb(self):
        body = "<title>KeeWeb</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-keeweb"

    def test_pleasant(self):
        body = "<title>Pleasant Password Server</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-pleasant"

    def test_psono(self):
        body = "<title>Psono - Password Manager</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-psono"

    def test_teampass(self):
        body = "<title>Teampass</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            finding = _check_password_manager(_svc())
        assert finding is not None
        assert finding.rule_id == "password-manager-teampass"


# ---------------------------------------------------------------------------
# Negative — must NOT flag
# ---------------------------------------------------------------------------


class TestNegative:
    def test_regular_webapp_no_flag(self):
        body = "<title>Login | Britimp Internal</title><h1>Welcome</h1>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            assert _check_password_manager(_svc()) is None

    def test_curl_failure_no_flag(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl("", code=0)):
            assert _check_password_manager(_svc()) is None

    def test_non_web_port_skipped(self):
        """Service on a non-canonical web port AND with non-web service
        name should be skipped early."""
        svc = DiscoveredService(host="h", port=5432, state="open", service="postgresql", product="")
        # No curl call needed because the gate rejects.
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl("", code=0)):
            assert _check_password_manager(svc) is None

    def test_word_password_alone_no_flag(self):
        """Just the word 'password' or 'login' shouldn't false-positive."""
        body = "<title>Login</title><form>Enter password</form>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            assert _check_password_manager(_svc()) is None


# ---------------------------------------------------------------------------
# Port routing — accepts canonical web ports
# ---------------------------------------------------------------------------


class TestPortRouting:
    def test_port_443_https(self):
        body = "<title>Vaultwarden Web</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            assert _check_password_manager(_svc(port=443)) is not None

    def test_port_80_http(self):
        body = "<title>Vaultwarden Web</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            assert _check_password_manager(_svc(port=80)) is not None

    def test_port_8443_alternative(self):
        body = "<title>Vaultwarden Web</title>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl(body)):
            assert _check_password_manager(_svc(port=8443)) is not None
