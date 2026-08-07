"""F198 — Asterisk discover (SIP OPTIONS + AMI banner)."""

from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.tools.voice.asterisk_discover import (
    AsteriskFingerprint,
    _build_sip_options,
    _fingerprint_one,
)


class TestBuildSipOptions:
    def test_includes_target_in_uri(self):
        payload = _build_sip_options("10.0.0.50")
        assert b"sip:10.0.0.50" in payload

    def test_uses_options_method(self):
        payload = _build_sip_options("10.0.0.50")
        assert payload.startswith(b"OPTIONS ")

    def test_includes_branch_magic_cookie(self):
        # RFC 3261 §8.1.1.7 — Via branch MUST start with z9hG4bK.
        payload = _build_sip_options("10.0.0.50")
        assert b"z9hG4bK" in payload


class TestFingerprintComposite:
    def test_asterisk_via_ami_banner(self):
        with (
            patch("kryon.tools.voice.asterisk_discover._probe_sip", return_value=(False, "", "")),
            patch("kryon.tools.voice.asterisk_discover._probe_ami", return_value=(True, "2.10.6")),
        ):
            fp = _fingerprint_one("10.0.0.50", 5060, 5038)
        assert fp.is_asterisk is True
        assert fp.ami_responded is True
        assert fp.ami_version == "2.10.6"

    def test_asterisk_via_sip_user_agent(self):
        with (
            patch(
                "kryon.tools.voice.asterisk_discover._probe_sip",
                return_value=(True, "Asterisk PBX 20.5.1", ""),
            ),
            patch("kryon.tools.voice.asterisk_discover._probe_ami", return_value=(False, "")),
        ):
            fp = _fingerprint_one("10.0.0.50", 5060, 5038)
        assert fp.is_asterisk is True
        assert fp.sip_user_agent == "Asterisk PBX 20.5.1"

    def test_freepbx_detection(self):
        with (
            patch(
                "kryon.tools.voice.asterisk_discover._probe_sip",
                return_value=(True, "FPBX-16.0.40(18.20.0)", ""),
            ),
            patch("kryon.tools.voice.asterisk_discover._probe_ami", return_value=(False, "")),
        ):
            fp = _fingerprint_one("10.0.0.50", 5060, 5038)
        assert fp.is_asterisk is True

    def test_non_asterisk_sip_server(self):
        with (
            patch(
                "kryon.tools.voice.asterisk_discover._probe_sip",
                return_value=(True, "Kamailio/5.7.4", "Kamailio/5.7.4"),
            ),
            patch("kryon.tools.voice.asterisk_discover._probe_ami", return_value=(False, "")),
        ):
            fp = _fingerprint_one("10.0.0.50", 5060, 5038)
        assert fp.is_asterisk is False
        assert fp.sip_responded is True

    def test_no_response(self):
        with (
            patch("kryon.tools.voice.asterisk_discover._probe_sip", return_value=(False, "", "")),
            patch("kryon.tools.voice.asterisk_discover._probe_ami", return_value=(False, "")),
        ):
            fp = _fingerprint_one("10.0.0.50", 5060, 5038)
        assert fp.is_asterisk is False
        assert fp.sip_responded is False
        assert fp.ami_responded is False


class TestAsteriskFingerprintDataclass:
    def test_frozen(self):
        fp = AsteriskFingerprint(host="10.0.0.50")
        with pytest.raises((AttributeError, TypeError)):
            fp.is_asterisk = True  # type: ignore[misc]

    def test_to_dict_round_trip(self):
        fp = AsteriskFingerprint(
            host="10.0.0.50",
            ami_responded=True,
            ami_version="2.10.6",
            is_asterisk=True,
        )
        d = fp.to_dict()
        assert d["host"] == "10.0.0.50"
        assert d["ami_version"] == "2.10.6"
        assert d["is_asterisk"] is True
