"""F202.P — Network printer / MFP family detection.

Surfaced POC Britimp 2026-05-19 contra .200.249: Kyocera MFP con
`Server: KM-MFP-http/V0.0.1` + path `/wlmesp/`. Originalmente
misclasificado (heuristica "9090 Cockpit + 9100 Prometheus") — el
:9100 es JetDirect raw-print + :9090 admin web de la impresora.

F202.P agrega:
  - banner markers: km-mfp, kyocera, hp-chai, lexmark, brother,
    canon, xerox, konica minolta, ricoh, samsung sps, epson, sharp
  - body markers: /wlmesp/, /web/guest/en/websys/, /hp/device/webaccess,
    /cgi-bin/syncthru, Command Center, etc.
  - port combos: 80+9100, 443+9100, 80+631 (IPP/CUPS), 80+515 (LPD)
  - `printer` family in appliance_families (suprimir Linux CIS FP)
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _PRINTER_BANNER_MARKERS,
    _PRINTER_BODY_MARKERS,
    _PRINTER_PORT_COMBOS,
    DiscoveredService,
    _detect_device_families,
)


def _svc(port: int, service: str = "", product: str = "", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host="h", port=port, state=state, service=service, product=product)


def _fake_curl_body(body: str, code: int = 200):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{body}\n__HTTPCODE__{code}", stderr="")

    return _run


def _fake_curl_empty():
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="\n__HTTPCODE__0", stderr="")

    return _run


# ---------------------------------------------------------------------------
# Banner markers — Kyocera (POC .200.249 reference case)
# ---------------------------------------------------------------------------


class TestKyoceraDetection:
    def test_km_mfp_banner_promotes_printer(self):
        """The exact .200.249 case: `Server: KM-MFP-http/V0.0.1`."""
        services = [_svc(443, "https", "KM-MFP-http/V0.0.1")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_kyocera_full_banner(self):
        services = [_svc(80, "http", "Kyocera ECOSYS M3145idn")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_taskalfa_banner(self):
        services = [_svc(80, "http", "TASKalfa 3253ci")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families


# ---------------------------------------------------------------------------
# Banner markers — other vendors
# ---------------------------------------------------------------------------


class TestOtherVendors:
    def test_hp_chaisoe(self):
        services = [_svc(80, "http", "HP-ChaiSOE/1.0")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_lexmark(self):
        services = [_svc(443, "https", "Lexmark MX series")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_brother(self):
        services = [_svc(80, "http", "Brother MFC-L2750DW")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_konica_minolta(self):
        services = [_svc(443, "https", "Konica Minolta bizhub C258")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families


# ---------------------------------------------------------------------------
# Port combos — JetDirect / IPP / LPD
# ---------------------------------------------------------------------------


class TestPortCombos:
    def test_80_9100_jetdirect(self):
        services = [_svc(80, "http", ""), _svc(9100, "jetdirect", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_443_9100_jetdirect_tls(self):
        services = [_svc(443, "https", ""), _svc(9100, "jetdirect", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_ipp_631_cups(self):
        services = [_svc(80, "http", ""), _svc(631, "ipp", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_lpd_515(self):
        services = [_svc(80, "http", ""), _svc(515, "lpd", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families


# ---------------------------------------------------------------------------
# Body markers (HTTP root content)
# ---------------------------------------------------------------------------


class TestBodyMarkers:
    def test_wlmesp_path(self):
        """The exact .200.249 case: HTTP root references /wlmesp/."""
        services = [_svc(443, "https", "")]
        body = '<html><body><a href="/wlmesp/index.htm">Login</a></body></html>'
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_command_center_marker(self):
        services = [_svc(80, "http", "")]
        body = "<html><title>Command Center RX</title></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "printer" in families

    def test_hp_device_webaccess(self):
        services = [_svc(80, "http", "")]
        body = "<a href='/hp/device/webaccess/'>Admin</a>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "printer" in families


# ---------------------------------------------------------------------------
# Appliance suppression — Linux CIS must NOT fire on printer
# ---------------------------------------------------------------------------


class TestLinuxSuppression:
    def test_printer_with_ssh_no_linux(self):
        """Some MFPs expose SSH for service tech. CIS Linux must NOT
        auto-add when `printer` family is detected."""
        services = [
            _svc(22, "ssh", "OpenSSH for embedded service tech"),
            _svc(443, "https", "KM-MFP-http/V0.0.1"),
            _svc(9100, "jetdirect", ""),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" in families
        assert "linux" not in families


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


class TestNegative:
    def test_regular_nginx_no_printer(self):
        services = [_svc(80, "http", "nginx 1.29.8"), _svc(443, "ssl/http", "nginx 1.29.8")]
        body = "<html><body>Britimp Internal</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "printer" not in families

    def test_apache_no_printer(self):
        services = [_svc(80, "http", "Apache/2.4.62")]
        body = "<html><body>Welcome</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "printer" not in families

    def test_just_80_alone_no_printer(self):
        services = [_svc(80, "http", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "printer" not in families


# ---------------------------------------------------------------------------
# Marker table sanity
# ---------------------------------------------------------------------------


class TestMarkerSanity:
    def test_km_mfp_in_banner_markers(self):
        assert "km-mfp" in _PRINTER_BANNER_MARKERS

    def test_wlmesp_in_body_markers(self):
        assert "/wlmesp/" in _PRINTER_BODY_MARKERS

    def test_80_9100_in_combos(self):
        assert frozenset({80, 9100}) in _PRINTER_PORT_COMBOS

    def test_all_lowercase(self):
        for m in _PRINTER_BANNER_MARKERS:
            assert m == m.lower(), f"Banner marker not lowercase: {m!r}"
        for m in _PRINTER_BODY_MARKERS:
            assert m == m.lower(), f"Body marker not lowercase: {m!r}"
