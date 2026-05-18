"""F197 — ONVIF WS-Discovery probe.

Tests focus on the pure parsing logic. The actual UDP multicast send/
receive is mocked because it requires real network I/O.
"""

from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.tools.iot.onvif_probe import (
    OnvifDevice,
    _build_probe,
    _parse_response,
)

# ---------------------------------------------------------------------------
# Probe envelope construction
# ---------------------------------------------------------------------------


class TestBuildProbe:
    def test_includes_message_id(self):
        payload = _build_probe("abc-1234")
        assert b"uuid:abc-1234" in payload

    def test_targets_network_video_transmitter(self):
        payload = _build_probe("abc")
        assert b"NetworkVideoTransmitter" in payload

    def test_is_valid_soap_envelope(self):
        payload = _build_probe("abc")
        assert payload.startswith(b'<?xml version="1.0"')
        assert b"<e:Envelope" in payload
        assert b"</e:Envelope>" in payload


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


_SAMPLE_HIKVISION_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:Scopes>onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/hardware/DS-2CD2042WD-I onvif://www.onvif.org/name/HIKVISION_DS-2CD2042WD-I</d:Scopes>
        <d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </e:Body>
</e:Envelope>
"""


class TestParseResponse:
    def test_extracts_xaddrs(self):
        d = _parse_response(_SAMPLE_HIKVISION_RESPONSE, "192.168.1.50:3702")
        assert "http://192.168.1.50/onvif/device_service" in d.xaddrs

    def test_extracts_types(self):
        d = _parse_response(_SAMPLE_HIKVISION_RESPONSE, "192.168.1.50:3702")
        assert "dn:NetworkVideoTransmitter" in d.types

    def test_extracts_scopes_with_vendor_info(self):
        d = _parse_response(_SAMPLE_HIKVISION_RESPONSE, "192.168.1.50:3702")
        # Scopes contain vendor markers like the hardware model
        joined = " ".join(d.scopes)
        assert "HIKVISION" in joined or "hikvision" in joined.lower()
        assert "DS-2CD2042WD-I" in joined

    def test_handles_empty_body(self):
        d = _parse_response("", "10.0.0.5:3702")
        assert d.xaddrs == []
        assert d.types == []
        assert d.scopes == []
        assert d.source_addr == "10.0.0.5:3702"


# ---------------------------------------------------------------------------
# Dataclass invariants
# ---------------------------------------------------------------------------


class TestOnvifDeviceDataclass:
    def test_dataclass_is_frozen(self):
        d = OnvifDevice(source_addr="10.0.0.5:3702")
        with pytest.raises((AttributeError, TypeError)):
            d.source_addr = "10.0.0.6:3702"  # type: ignore[misc]

    def test_to_dict_round_trip(self):
        d = OnvifDevice(
            source_addr="10.0.0.5:3702",
            xaddrs=["http://10.0.0.5/onvif/device_service"],
            types=["dn:NetworkVideoTransmitter"],
        )
        out = d.to_dict()
        assert out["source_addr"] == "10.0.0.5:3702"
        assert out["xaddrs"] == ["http://10.0.0.5/onvif/device_service"]
