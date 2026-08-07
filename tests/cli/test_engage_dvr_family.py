"""F201.A — DVR / IP camera / NVR device family detection.

Regression test for the FP observed in the Example POC pilot on
2026-05-18: 192.0.2.12 was a Hikvision NVR running on Windows
(open ports 80, 135, 139, 443, 445, 554, 5357, 7070, 8081). The
old detector tagged it `windows` + `windows_ad` and fired 24 CIS
FAILs against vendor firmware that cannot accept registry edits,
local user policies, or GPO.

The fix:
  - new `dvr` family in `_DEVICE_FAMILIES`
  - banner-marker detection (Hikvision / Dahua / Axis / TVT / Uniview)
  - port-combo detection (554+7070 for Hikvision, 554+37777 for Dahua)
  - HTTP body fetch fallback (CSP `*.hikvision.com`, ISAPI paths)
  - `dvr` added to `appliance_families` so Linux CIS does NOT auto-add
  - `windows` / `windows_ad` scrubbed when `dvr` is detected (NVR is
    sealed appliance regardless of the underlying OS)
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _detect_device_families


def _svc(host: str, port: int, service: str = "", product: str = "", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service=service, product=product)


def _fake_curl_empty():
    """Patches _http_get's subprocess.run so the body-marker fallback
    returns an empty body (no false-positive triggering)."""

    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="\n__HTTPCODE__0", stderr="")

    return _run


def _fake_curl_body(body: str, code: int = 200):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{body}\n__HTTPCODE__{code}", stderr="")

    return _run


# ---------------------------------------------------------------------------
# Banner-based detection
# ---------------------------------------------------------------------------


class TestBannerMarkers:
    def test_hikvision_banner_promotes_dvr(self):
        services = [_svc("h", 443, "https", "Hikvision IP camera web interface")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_dahua_banner_promotes_dvr(self):
        services = [_svc("h", 80, "http", "Dahua DVR web")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_axis_banner_promotes_dvr(self):
        services = [_svc("h", 80, "http", "Axis Communications camera")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_onvif_banner_promotes_dvr(self):
        services = [_svc("h", 80, "http", "ONVIF service")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families


# ---------------------------------------------------------------------------
# Port-combo detection (the .12 regression case)
# ---------------------------------------------------------------------------


class TestPortComboHikvision:
    def test_example_h12_scenario(self):
        """The exact .12 case: Windows-hosted Hikvision NVR. Banner is
        anonymized (Server: -) but port combo 554+7070+8081 is diagnostic."""
        services = [
            _svc("h", 80, "http", ""),  # anonymized HTTP
            _svc("h", 135, "msrpc", "Microsoft Windows RPC"),
            _svc("h", 139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
            _svc("h", 443, "https", ""),
            _svc("h", 445, "microsoft-ds", ""),
            _svc("h", 554, "rtsp", ""),
            _svc("h", 5357, "http", "Microsoft HTTPAPI httpd 2.0"),
            _svc("h", 7070, "realserver", ""),
            _svc("h", 8081, "blackice-icecap", ""),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families, f"Expected dvr in families, got {families}"
        # F201.A — windows / windows_ad must be scrubbed when dvr is detected.
        assert "windows" not in families
        assert "windows_ad" not in families

    def test_hikvision_minimal_combo_554_7070(self):
        services = [_svc("h", 554, "rtsp", ""), _svc("h", 7070, "realserver", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families


class TestPortComboDahua:
    def test_dahua_combo_554_37777(self):
        services = [_svc("h", 554, "rtsp", ""), _svc("h", 37777, "dahua-dvr", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_dahua_alt_combo_554_37778(self):
        services = [_svc("h", 554, "rtsp", ""), _svc("h", 37778, "", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families


# ---------------------------------------------------------------------------
# HTTP body marker fallback
# ---------------------------------------------------------------------------


class TestBodyMarkers:
    def test_hikvision_csp_body_marker(self):
        """Anonymized banner + no port combo, but HTTP body contains
        Hikvision CSP — body fetch fallback kicks in."""
        services = [_svc("h", 443, "https", "")]
        csp_body = (
            "<!doctype html><html><head><meta http-equiv='Content-Security-Policy' "
            "content=\"default-src 'self' https://*.hikvision.com\"></head></html>"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(csp_body)):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_dahua_body_marker(self):
        services = [_svc("h", 80, "http", "")]
        body = "<html><script src='/cgi-bin/magicBox.cgi?action=getDeviceType'></script></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" in families

    def test_isapi_path_body_marker(self):
        services = [_svc("h", 80, "http", "")]
        body = "<html><body><a href='/ISAPI/Security/userCheck'>login</a></body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" in families


# ---------------------------------------------------------------------------
# Windows scrubbing — F201.A core invariant
# ---------------------------------------------------------------------------


class TestWindowsScrubbing:
    def test_dvr_scrubs_windows_ad(self):
        """Even though SMB+RPC+LDAP are open, dvr family must scrub
        windows_ad — a Hikvision NVR is NOT a domain controller."""
        services = [
            _svc("h", 88, "kerberos", ""),
            _svc("h", 135, "msrpc", "Microsoft Windows RPC"),
            _svc("h", 389, "ldap", ""),
            _svc("h", 445, "microsoft-ds", ""),
            _svc("h", 554, "rtsp", ""),
            _svc("h", 7070, "realserver", ""),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families
        assert "windows_ad" not in families
        assert "windows" not in families

    def test_dvr_alone_no_windows(self):
        services = [
            _svc("h", 554, "rtsp", ""),
            _svc("h", 7070, "realserver", ""),
            _svc("h", 80, "http", "Hikvision IP camera"),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert families == ["dvr"]


# ---------------------------------------------------------------------------
# Linux CIS suppression — DVR is in appliance_families set
# ---------------------------------------------------------------------------


class TestLinuxSuppressed:
    def test_dvr_with_ssh_no_linux(self):
        """Some Hikvision firmware exposes a sshd for debug — but it's
        sealed, you can't edit sshd_config. CIS Linux must NOT auto-add."""
        services = [
            _svc("h", 22, "ssh", "OpenSSH"),
            _svc("h", 80, "http", "Hikvision web"),
            _svc("h", 554, "rtsp", ""),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" in families
        assert "linux" not in families


# ---------------------------------------------------------------------------
# Negative cases — generic Windows / Linux must STILL be detected
# ---------------------------------------------------------------------------


class TestNegativeRegressions:
    def test_generic_windows_no_dvr(self):
        """Bare Windows host (no RTSP, no Hikvision banner) stays as windows + windows_ad."""
        services = [
            _svc("h", 135, "msrpc", "Microsoft Windows RPC"),
            _svc("h", 139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
            _svc("h", 445, "microsoft-ds", ""),
            _svc("h", 3389, "ms-wbt-server", ""),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" not in families
        assert "windows" in families

    def test_generic_ubuntu_no_dvr(self):
        services = [
            _svc("h", 22, "ssh", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.15"),
            _svc("h", 80, "http", "nginx 1.18.0 (Ubuntu)"),
        ]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" not in families
        assert "linux" in families

    def test_rtsp_alone_no_dvr(self):
        """RTSP on 554 alone is too generic — media servers (VLC,
        FFserver, Wowza) all use 554. Without 7070/37777 or a banner
        marker, do NOT promote to dvr."""
        services = [_svc("h", 554, "rtsp", "")]
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_empty()):
            families = _detect_device_families(services)
        assert "dvr" not in families

    def test_regular_html_no_dvr_marker(self):
        services = [_svc("h", 80, "http", "")]
        body = "<html><body>Welcome to Example Internal</body></html>"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_curl_body(body)):
            families = _detect_device_families(services)
        assert "dvr" not in families
