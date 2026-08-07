"""F197 — ONVIF WS-Discovery probe (UDP 3702 multicast).

Discovers ONVIF-compliant devices (IP cameras, NVRs, encoders) on the
local broadcast domain by sending a WS-Discovery Probe and collecting
responses. Faster than fingerprinting host-by-host when the target
segment is large.

Limitations:
  - Multicast may not propagate across L3 boundaries. If the operator
    is on a different VLAN than the cameras, this won't find them
    (use `dvr_fingerprint` per-IP instead).
  - Some firewalls drop UDP 3702 outbound.
  - Replies arrive asynchronously — we collect for `timeout_s` seconds
    and parse what came back. Tune `timeout_s` for noisy networks.
"""

from __future__ import annotations

import re
import socket
import struct
import uuid
from dataclasses import asdict, dataclass, field

from kryon.sdk.agents import function_tool

_WS_DISCOVERY_ADDR = "239.255.255.250"
_WS_DISCOVERY_PORT = 3702


def _build_probe(message_id: str) -> bytes:
    """Standard ONVIF WS-Discovery Probe envelope (RFC + ONVIF spec)."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        "<e:Header>"
        f"<w:MessageID>uuid:{message_id}</w:MessageID>"
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        "</e:Header>"
        "<e:Body>"
        "<d:Probe>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "</d:Probe>"
        "</e:Body>"
        "</e:Envelope>"
    ).encode()


@dataclass(frozen=True)
class OnvifDevice:
    """A single device that responded to the WS-Discovery probe."""

    source_addr: str  # IP:port from the UDP packet
    xaddrs: list[str] = field(default_factory=list)  # device service URLs advertised
    types: list[str] = field(default_factory=list)  # ONVIF Types: NetworkVideoTransmitter, etc.
    scopes: list[str] = field(default_factory=list)  # ONVIF Scopes (vendor/model hints)
    raw: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_XADDRS_RE = re.compile(r"<d:XAddrs>([^<]+)</d:XAddrs>", re.IGNORECASE)
_TYPES_RE = re.compile(r"<d:Types>([^<]+)</d:Types>", re.IGNORECASE)
_SCOPES_RE = re.compile(r"<d:Scopes>([^<]+)</d:Scopes>", re.IGNORECASE)


def _parse_response(raw: str, source_addr: str) -> OnvifDevice:
    """Extract XAddrs / Types / Scopes from a WS-Discovery ProbeMatches body."""
    xaddrs_m = _XADDRS_RE.search(raw)
    xaddrs = xaddrs_m.group(1).split() if xaddrs_m else []

    types_m = _TYPES_RE.search(raw)
    types = types_m.group(1).split() if types_m else []

    scopes_m = _SCOPES_RE.search(raw)
    scopes = scopes_m.group(1).split() if scopes_m else []

    return OnvifDevice(
        source_addr=source_addr,
        xaddrs=xaddrs,
        types=types,
        scopes=scopes,
        raw=raw[:2048],
    )


def _send_and_collect(timeout_s: int) -> list[OnvifDevice]:
    """Send the WS-Discovery probe and collect responses for `timeout_s`."""
    msg_id = str(uuid.uuid4())
    payload = _build_probe(msg_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # TTL=2 so the probe crosses one L3 hop if multicast routing is enabled.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2))
    sock.settimeout(timeout_s)

    devices: list[OnvifDevice] = []
    try:
        sock.sendto(payload, (_WS_DISCOVERY_ADDR, _WS_DISCOVERY_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(8192)
            except TimeoutError:
                break
            except OSError:
                break
            raw = data.decode("utf-8", errors="replace")
            if "ProbeMatch" not in raw and "Envelope" not in raw:
                continue
            devices.append(_parse_response(raw, f"{addr[0]}:{addr[1]}"))
    finally:
        sock.close()

    return devices


@function_tool
def onvif_discover(timeout_s: int = 5) -> str:
    """Discover ONVIF-compliant cameras / NVRs on the local broadcast domain.

    Sends a WS-Discovery Probe to the standard multicast address
    (239.255.255.250:3702) and collects ProbeMatches for `timeout_s`
    seconds. Read-only — no authentication, no exploit attempts.

    Args:
        timeout_s: How long to listen for responses (default: 5 seconds).
            Tune higher for noisy networks where devices respond slowly.

    Returns:
        Human-readable list of discovered devices with their device service
        URLs (xaddrs), types, and scopes (often containing vendor/model).

    Examples:
        onvif_discover()                # 5-second sweep
        onvif_discover(timeout_s=10)    # patient sweep for slow networks
    """
    if timeout_s <= 0 or timeout_s > 60:
        return f"onvif_discover: timeout_s must be in [1, 60], got {timeout_s}"

    devices = _send_and_collect(timeout_s)

    if not devices:
        return (
            "onvif_discover: no ONVIF devices responded.\n"
            "Possible reasons:\n"
            "  - No cameras on this broadcast domain.\n"
            "  - Multicast (239.255.255.250:3702) blocked by switch/firewall.\n"
            "  - Operator on different VLAN/subnet than the cameras.\n"
            "  - Cameras have ONVIF disabled.\n"
            "Fallback: use `dvr_fingerprint` per host IP."
        )

    lines = [f"onvif_discover: {len(devices)} device(s) responded\n"]
    for i, d in enumerate(devices, start=1):
        lines.append(f"[{i}] source={d.source_addr}")
        if d.xaddrs:
            lines.append(f"    xaddrs: {' '.join(d.xaddrs)}")
        if d.types:
            lines.append(f"    types: {' '.join(d.types)}")
        if d.scopes:
            scope_lines = [s for s in d.scopes if "onvif" in s.lower()]
            lines.append(f"    scopes: {' '.join(scope_lines[:5])}")
    return "\n".join(lines)


__all__ = ["onvif_discover", "OnvifDevice"]
