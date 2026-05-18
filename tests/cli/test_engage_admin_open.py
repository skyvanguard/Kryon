"""F199.H — http-admin-open no debe flag cuando /admin = SPA catch-all.

Surfaceado en el POC piloto de Britimp 2026-05-18 contra .123, una
SPA Angular ("Registro de Visitas") cuyo nginx config sirve index.html
para cualquier path (HTML5 routing). Kryon flag-eaba CWE-306 "admin
sin auth" aunque /admin no era un endpoint admin real.

F199.H compara la respuesta de /admin contra la del root /. Si bodies
son identicos (length + sha256) → SPA catch-all → no flag. Si difieren
→ admin real expuesto → flag HIGH.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_admin_open


def _svc(host: str = "10.0.0.5", port: int = 80) -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state="open", service="http", product="")


def _fake_curl_factory(responses: dict[str, tuple[int, str]]):
    """Returns a fake subprocess.run that responds based on the URL in argv.

    `responses` maps URL substring → (status, body).
    """

    def _run(cmd, **_kw):
        url = cmd[-1] if isinstance(cmd, list) else ""
        for key, (code, body) in responses.items():
            if key in url:
                stdout = f"{body}\n__HTTPCODE__{code}"
                return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="\n__HTTPCODE__000", stderr="")

    return _run


# ---------------------------------------------------------------------------
# SPA catch-all — must NOT flag
# ---------------------------------------------------------------------------


class TestSpaCatchAll:
    def test_angular_spa_identical_body_no_flag(self):
        """The exact case from .123 (Britimp Registro de Visitas SPA)."""
        spa_body = "<!doctype html><html><base href='/'><body>Britimp</body></html>"
        responses = {
            "/admin": (200, spa_body),
            "/": (200, spa_body),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            finding = _check_admin_open(_svc())
        assert finding is None, "SPA catch-all must not flag http-admin-open"

    def test_react_spa_html5_routing_no_flag(self):
        body = '<!doctype html><html id="root"></html>'
        responses = {
            "/admin": (200, body),
            "/": (200, body),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            assert _check_admin_open(_svc()) is None


# ---------------------------------------------------------------------------
# Real admin endpoint — must flag
# ---------------------------------------------------------------------------


class TestRealAdminEndpoint:
    def test_distinct_admin_html_flags_high(self):
        responses = {
            "/admin": (200, "<html><h1>Admin Console</h1><form>login</form></html>"),
            "/": (200, "<html><h1>Welcome</h1></html>"),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            finding = _check_admin_open(_svc())
        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-306"
        assert finding.rule_id == "http-admin-open"

    def test_admin_when_root_404_still_flag(self):
        """Some apps don't have a root page but do have /admin. The fact
        that /admin returns 200 with content is suspicious in itself."""
        responses = {
            "/admin": (200, "<html>Admin Console</html>"),
            "/": (404, "404 Not Found"),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            finding = _check_admin_open(_svc())
        assert finding is not None
        assert finding.severity == "HIGH"


# ---------------------------------------------------------------------------
# Non-200 /admin — must NOT flag
# ---------------------------------------------------------------------------


class TestNon200Admin:
    def test_admin_404_no_flag(self):
        responses = {
            "/admin": (404, "404 Not Found"),
            "/": (200, "<html>Welcome</html>"),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            assert _check_admin_open(_svc()) is None

    def test_admin_401_no_flag(self):
        """401 = auth required, that's PASS behaviour."""
        responses = {
            "/admin": (401, "Unauthorized"),
            "/": (200, "<html>Welcome</html>"),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            assert _check_admin_open(_svc()) is None

    def test_admin_403_no_flag(self):
        responses = {
            "/admin": (403, "Forbidden"),
            "/": (200, "<html>Welcome</html>"),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            assert _check_admin_open(_svc()) is None

    def test_admin_connect_failure_no_flag(self):
        """curl returns 000 on connection failure."""
        responses = {
            "/admin": (0, ""),
            "/": (200, "<html>Welcome</html>"),
        }
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_factory(responses)):
            assert _check_admin_open(_svc()) is None
