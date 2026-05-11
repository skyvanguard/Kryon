"""F84.4 — IEC 60870-5-104 audit tool.

IEC 60870-5-104 (often "IEC 104") is the dominant SCADA protocol for
power utility telecontrol in Europe + LATAM. Used by ANDE Paraguay,
ENDE Bolivia, Edesur Argentina, ENDESA Chile to talk to substation
RTUs over WAN. Like DNP3/Modbus, the base protocol has no auth — the
"IEC 62351" overlay specifies TLS + certificate-based auth but real
deployments rarely deploy it.

Frame layout (APCI = Application Protocol Control Information):

  Byte 0   : 0x68 (start)
  Byte 1   : APDU length (bytes following, max 253)
  Bytes 2-5: Control field (4 bytes, format depends on type)

Three frame formats encoded in the control bits:
  I-format (Information): bit 0 of byte 2 = 0 → NS|NR sequence numbers
  S-format (Supervisory): bits = 01     → ack-only (NR only)
  U-format (Unnumbered):  bits = 11     → STARTDT/STOPDT/TESTFR

This module probes:
  1. TCP connect to 2404/tcp
  2. Send STARTDT activation (U-format, control = 0x07000000)
  3. Expect STARTDT confirmation (control = 0x0B000000)
  4. (optional) send TESTFR activation (control = 0x43000000) and
     expect confirmation (0x83000000) — proves the link is "alive"
  5. STOPDT cleanup so we don't leave the session hanging

Any STARTDT confirmation from an arbitrary source = anonymous control
access established → CRITICAL per IEC 62443 SR 1.1 + NERC CIP-007 R5.

References:
  - IEC 60870-5-104:2006 (Network access for IEC 60870-5-101)
  - IEC 62351-3 (TLS for power systems)
  - NERC CIP-005 R1, CIP-007 R5
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

IEC104_DEFAULT_PORT = 2404
_CONNECT_TIMEOUT_S = 3.0
_READ_TIMEOUT_S = 3.0

# U-format control field constants (big-endian for clarity; the wire is
# little-endian-ish per spec but the type bits are bit-positions).
_STARTDT_ACT = 0x07
_STARTDT_CON = 0x0B
_STOPDT_ACT = 0x13
_STOPDT_CON = 0x23
_TESTFR_ACT = 0x43
_TESTFR_CON = 0x83


@dataclass(frozen=True)
class IEC104ProbeResult:
    """Outcome of probing one IEC 60870-5-104 target."""

    host: str
    port: int
    reachable: bool
    responds_to_iec104: bool       # any valid 0x68 frame received
    startdt_confirmed: bool        # session control activation succeeded
    testfr_confirmed: bool         # link alive ack received
    error: str = ""

    @property
    def has_unauth_exposure(self) -> bool:
        """STARTDT activation succeeded without prior auth = exposed."""
        return self.startdt_confirmed


# ---------- Frame helpers ----------


def _build_u_frame(control_byte: int) -> bytes:
    """Build a U-format APCI: 0x68 0x04 control 0x00 0x00 0x00."""
    return struct.pack(">BBBBBB", 0x68, 0x04, control_byte, 0x00, 0x00, 0x00)


def _is_iec104_frame(response: bytes) -> bool:
    """Cheapest sanity check: starts with 0x68 and APDU length is sane."""
    if len(response) < 2:
        return False
    if response[0] != 0x68:
        return False
    declared = response[1]
    return 4 <= declared <= 253


def _is_u_frame_response(response: bytes, expected_control: int) -> bool:
    """Verify the response is a U-format frame with the expected control byte."""
    if not _is_iec104_frame(response):
        return False
    if len(response) < 6:
        return False
    return response[2] == expected_control


# ---------- Socket I/O ----------


def _send_recv(sock: socket.socket, data: bytes) -> bytes:
    """Send + read a single APDU. APDUs are framed by length so we can
    read precisely the bytes we need without timeouts."""
    sock.settimeout(_READ_TIMEOUT_S)
    sock.sendall(data)

    # Read APCI start (2 bytes minimum to know declared length).
    header = b""
    while len(header) < 2:
        chunk = sock.recv(2 - len(header))
        if not chunk:
            break
        header += chunk
    if len(header) < 2 or header[0] != 0x68:
        return header

    declared = header[1]
    body = b""
    target = declared  # bytes following the length byte
    while len(body) < target:
        chunk = sock.recv(target - len(body))
        if not chunk:
            break
        body += chunk
    return header + body


# ---------- Public API ----------


def iec104_probe(
    host: str,
    *,
    port: int = IEC104_DEFAULT_PORT,
    test_link_alive: bool = True,
) -> IEC104ProbeResult:
    """Probe a target for IEC 60870-5-104 exposure.

    Args:
        host: target IP/hostname.
        port: 2404 by default.
        test_link_alive: when True, also send TESTFR activation after
            STARTDT — proves the link reaches the controller (some
            firewalls forward STARTDT but block subsequent traffic).

    The probe is read-only — it never sends Interrogation, control, or
    Set-Point commands. Sending I-format command frames against a real
    substation RTU could trip breakers; we don't enable that even
    behind a flag.
    """
    # Step 1 — TCP reachability.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_CONNECT_TIMEOUT_S)
        sock.connect((host, port))
    except (TimeoutError, OSError) as e:
        return IEC104ProbeResult(
            host=host,
            port=port,
            reachable=False,
            responds_to_iec104=False,
            startdt_confirmed=False,
            testfr_confirmed=False,
            error=f"tcp_connect_failed: {type(e).__name__}",
        )

    try:
        # Step 2 — STARTDT activation.
        startdt_act = _build_u_frame(_STARTDT_ACT)
        try:
            response = _send_recv(sock, startdt_act)
        except (TimeoutError, OSError) as e:
            return IEC104ProbeResult(
                host=host,
                port=port,
                reachable=True,
                responds_to_iec104=False,
                startdt_confirmed=False,
                testfr_confirmed=False,
                error=f"startdt_send_failed: {type(e).__name__}",
            )

        responds = _is_iec104_frame(response)
        startdt_ok = _is_u_frame_response(response, _STARTDT_CON)

        if not startdt_ok:
            return IEC104ProbeResult(
                host=host,
                port=port,
                reachable=True,
                responds_to_iec104=responds,
                startdt_confirmed=False,
                testfr_confirmed=False,
            )

        # Step 3 — TESTFR activation (optional liveness check).
        testfr_ok = False
        if test_link_alive:
            testfr_act = _build_u_frame(_TESTFR_ACT)
            try:
                testfr_resp = _send_recv(sock, testfr_act)
                testfr_ok = _is_u_frame_response(testfr_resp, _TESTFR_CON)
            except (TimeoutError, OSError):
                testfr_ok = False

        # Step 4 — STOPDT to close cleanly.
        try:
            stopdt_act = _build_u_frame(_STOPDT_ACT)
            sock.sendall(stopdt_act)
            # Don't wait for ack — best-effort cleanup.
        except OSError:
            pass

        return IEC104ProbeResult(
            host=host,
            port=port,
            reachable=True,
            responds_to_iec104=True,
            startdt_confirmed=True,
            testfr_confirmed=testfr_ok,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass
