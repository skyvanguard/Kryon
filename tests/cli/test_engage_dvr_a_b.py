"""F201.A.B — DVR detection extended for Hikvision modern firmware.

Surface ground truth POC Example TORRE_USR 2026-05-19 contra .2 + .250:
ambos son Hikvision DVR/NVR con firmware 2020+. Banner anonimizado
(sin "hikvision" en product), RTSP filtrado, pero el body redirige a
`/doc/page/login.asp` con timestamp anti-cache y el SDK 8000 abierto.

Pre-F201.A.B: F201.A no detectaba el host como dvr (banner / combo
no matcheaban) -> generic Linux/Windows family con FPs CIS.

F201.A.B agrega:
  - body markers: `/doc/page/login.asp`, `/doc/page/login.htm`,
    `doc/page/wizard`, `server: webs`
  - port combos: {80, 8000} HTTP + SDK, {443, 8000} HTTPS + SDK
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _DVR_BODY_MARKERS,
    _DVR_PORT_COMBOS,
    DiscoveredService,
    _detect_device_families,
)


def _svc(port: int, service: str = "", product: str = "", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host="h", port=port, state=state, service=service, product=product)


def _fake_curl_body(body: str, code: int = 200):
    def _run(cmd, **_kw):
        stdout = f"{body}\n__HTTPCODE__{code}"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    return _run


def _fake_curl_empty():
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="\n__HTTPCODE__0", stderr="")

    return _run


# ---------------------------------------------------------------------------
# F201.A.B — Example TORRE_USR regression cases
# ---------------------------------------------------------------------------


class TestExampleTorreUsrH2:
    def test_h2_login_asp_body_marker(self):
        """The exact .2 case: HTTP body is a JS redirect to
        /doc/page/login.asp with timestamp. Must trigger dvr family."""
        services = [_svc(80, "http", ""), _svc(8000, "http-alt", "")]
        body = (
            "<!doctype html><html><head><title></title></head>"
            "<body></body>"
            '<script>window.location.href = "/doc/page/login.asp?_" + '
            "(new Date()).getTime();</script></html>"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" in families, f"Expected dvr in families, got {families}"

    def test_h2_port_combo_80_8000_sin_body(self):
        """Cuando el body fetch falla pero el port combo {80, 8000}
        esta presente, el detector debe inferir DVR."""
        services = [_svc(80, "http", ""), _svc(8000, "http-alt", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_h250_webs_server_header(self):
        """The .250 case: `Server: Webs` (Goahead WebServer embebido).
        Body fetch debe encontrar el header dentro del response."""
        services = [_svc(80, "http", "")]
        body = (
            "Server: Webs\r\n"
            "<!doctype html><html><body><script>"
            'window.location.href = "./doc/page/login.asp?_" + '
            "(new Date()).getTime();</script></body></html>"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" in families


# ---------------------------------------------------------------------------
# F201.A.B — Hikvision NVR variants
# ---------------------------------------------------------------------------


class TestHikvisionVariants:
    def test_login_htm_variant(self):
        services = [_svc(80, "http", "")]
        body = '<script>location.href = "/doc/page/login.htm";</script>'
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_setup_wizard_marker(self):
        services = [_svc(80, "http", "")]
        body = '<a href="/doc/page/wizard">First-time setup</a>'
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_443_8000_combo(self):
        services = [_svc(443, "https", ""), _svc(8000, "http-alt", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families


# ---------------------------------------------------------------------------
# Negative cases — must NOT FP on generic HTTP services
# ---------------------------------------------------------------------------


class TestNoFalsePositives:
    def test_regular_nginx_no_dvr(self):
        services = [_svc(80, "http", "nginx 1.29.8"), _svc(443, "ssl/http", "nginx 1.29.8")]
        body = "<html><body>Welcome to Example Internal</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" not in families

    def test_iis_admin_panel_no_dvr(self):
        services = [_svc(8000, "http-alt", "Microsoft IIS")]
        body = "<html><body>IIS Admin</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        # Note: 80 + 8000 sin 80 abierto, no debe FP.
        # Pero este test solo tiene 8000. 80 no esta abierto.
        # _DVR_PORT_COMBOS requiere AMBOS en open_ports.
        assert "dvr" not in families

    def test_port_8000_alone_no_dvr(self):
        """Port 8000 alone (web admin alt) -> no DVR."""
        services = [_svc(8000, "http-alt", "")]
        body = "<html><body>Admin</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" not in families


# ---------------------------------------------------------------------------
# Marker table sanity
# ---------------------------------------------------------------------------


class TestMarkerTableSanity:
    def test_login_asp_in_body_markers(self):
        assert "/doc/page/login.asp" in _DVR_BODY_MARKERS

    def test_webs_server_in_body_markers(self):
        assert "server: webs" in _DVR_BODY_MARKERS

    def test_80_8000_combo_in_port_combos(self):
        assert frozenset({80, 8000}) in _DVR_PORT_COMBOS

    def test_443_8000_combo_in_port_combos(self):
        assert frozenset({443, 8000}) in _DVR_PORT_COMBOS

    def test_all_body_markers_lowercase(self):
        for m in _DVR_BODY_MARKERS:
            assert m == m.lower(), f"Marker not lowercase: {m!r}"
