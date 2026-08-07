"""F197 — DVR fingerprinting recon tool.

These tests focus on the pure parsing/detection logic. Network I/O is
mocked so the tests are deterministic and run offline.
"""

from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.tools.iot.dvr_recon import (
    DvrFingerprint,
    _fingerprint_one,
)

# ---------------------------------------------------------------------------
# Hikvision detection
# ---------------------------------------------------------------------------


class TestHikvisionDetection:
    def test_app_webs_server_header_detects_hikvision(self):
        # Simulate an HTTP response where the Server header says App-WebS
        # (Hikvision marker).
        def fake_get(url, *, timeout_s=5):
            if url.endswith("/"):
                return (
                    200,
                    "App-WebS/2.0",
                    "<html><title>Hikvision Network Camera</title></html>",
                )
            if "/doc/page/login.asp" in url:
                return 200, "", "<html>DS-7608NI-K2/8P firmware 4.30.0</html>"
            return 0, "", ""

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        assert fp.vendor == "hikvision"
        assert "server-header-App-WebS" in fp.markers
        assert "title-Hikvision" in fp.markers
        assert "hikvision-login-asp-present" in fp.markers
        assert fp.model == "DS-7608NI-K2"

    def test_hikvision_title_alone_detects(self):
        def fake_get(url, *, timeout_s=5):
            if url.endswith("/"):
                return 200, "Apache/2.4", "<html><title>HIKVISION DVR</title></html>"
            return 401, "", ""  # /doc/page/login.asp returns 401 = present but auth required

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        assert fp.vendor == "hikvision"
        assert "title-Hikvision" in fp.markers
        assert "hikvision-login-asp-present" in fp.markers


# ---------------------------------------------------------------------------
# Dahua detection
# ---------------------------------------------------------------------------


class TestDahuaDetection:
    def test_webs_server_header_detects_dahua(self):
        def fake_get(url, *, timeout_s=5):
            if url.endswith("/"):
                return (
                    200,
                    "Webs",
                    "<html><title>Dahua DVR Web Service</title></html>",
                )
            if "/RPC2_Login" in url:
                return 200, "", '{"id":1,"result":false,"error":{"code":-32602}}'
            return 0, "", ""

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        assert fp.vendor == "dahua"
        assert "server-header-Webs" in fp.markers
        assert "dahua-rpc2-login-present" in fp.markers

    def test_boa_0_94_14_detects_dahua(self):
        def fake_get(url, *, timeout_s=5):
            if url.endswith("/"):
                return 200, "Boa/0.94.14", "<html></html>"
            if "/RPC2_Login" in url:
                return 405, "", ""
            return 0, "", ""

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        assert fp.vendor == "dahua"
        assert "server-header-Boa-0.94.14" in fp.markers


# ---------------------------------------------------------------------------
# Generic-DVR fallback
# ---------------------------------------------------------------------------


class TestGenericDvrFallback:
    def test_dvr_keyword_in_html_tags_as_generic(self):
        def fake_get(url, *, timeout_s=5):
            if url.endswith("/"):
                return (
                    200,
                    "lighttpd/1.4.55",
                    "<html><title>NVR Login</title>Welcome to our IPC system</html>",
                )
            return 0, "", ""

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        assert fp.vendor == "generic-dvr"
        assert "generic-dvr-keyword" in fp.markers


# ---------------------------------------------------------------------------
# Unknown handling
# ---------------------------------------------------------------------------


class TestUnknownDevice:
    def test_no_response_returns_unknown(self):
        def fake_get(url, *, timeout_s=5):
            return 0, "", ""

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        assert fp.vendor == "unknown"
        assert fp.markers == []
        assert fp.server_header == ""

    def test_nginx_generic_web_does_not_match(self):
        def fake_get(url, *, timeout_s=5):
            if url.endswith("/"):
                return 200, "nginx/1.18.0", "<html><title>Welcome</title></html>"
            return 0, "", ""

        with patch("kryon.tools.iot.dvr_recon._http_get", side_effect=fake_get):
            fp = _fingerprint_one("10.0.0.5", 80, "http")
        # The host responded but no DVR-specific markers fired.
        assert fp.vendor == "unknown"
        assert fp.server_header == "nginx/1.18.0"


# ---------------------------------------------------------------------------
# DvrFingerprint dataclass invariants
# ---------------------------------------------------------------------------


class TestDvrFingerprintDataclass:
    def test_dataclass_is_frozen(self):
        fp = DvrFingerprint(host="10.0.0.5", port=80)
        with pytest.raises((AttributeError, TypeError)):
            fp.vendor = "hikvision"  # type: ignore[misc]

    def test_to_dict_round_trip(self):
        fp = DvrFingerprint(
            host="10.0.0.5",
            port=80,
            vendor="hikvision",
            markers=["server-header-App-WebS"],
        )
        d = fp.to_dict()
        assert d["host"] == "10.0.0.5"
        assert d["vendor"] == "hikvision"
        assert d["markers"] == ["server-header-App-WebS"]
