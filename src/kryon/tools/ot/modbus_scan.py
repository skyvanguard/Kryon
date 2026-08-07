"""F84.1 — Modbus/TCP audit tool (stdlib-only).

Modbus/TCP is the most common industrial protocol on port 502. By design
it has zero authentication: anyone who can reach 502/tcp can read coils,
read holding registers, and (catastrophically) write to them. PCI-DSS
adjacent banking infra is increasingly OT-connected (HVAC, generators,
physical access controllers); a missed Modbus exposure on the corporate
LAN is a direct path to physical disruption.

This module probes a target via a tiny raw-socket implementation of the
Modbus Application Protocol Header (MBAP) plus a few function codes.
No external dependency — `pymodbus` is great but bringing in libraries
into a banking-container is friction we don't need for the audit
baseline.

Function codes implemented:
  0x01 — Read Coils                  → tests anonymous read access
  0x03 — Read Holding Registers      → tests anonymous read access
  0x05 — Write Single Coil           → tests anonymous WRITE (DANGEROUS;
                                        only attempted when caller passes
                                        `attempt_write=True` after written
                                        authorization on engagement letter)
  0x2B — Read Device Identification  → enumerate vendor/firmware string

References:
  - Modbus Application Protocol Specification v1.1b3 (Apr 26, 2012)
  - IEC 62443-3-3 SR 1.1 (identification and authentication)
  - NERC CIP-005 R1 (electronic security perimeter)
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# MBAP header structure (7 bytes):
#   transaction_id : uint16 BE
#   protocol_id    : uint16 BE (always 0x0000 for Modbus/TCP)
#   length         : uint16 BE (number of bytes following)
#   unit_id        : uint8     (slave address, 0xFF = broadcast on TCP)
_MBAP_FMT = ">HHHB"

# Default Modbus port and reasonable timeouts.
MODBUS_TCP_PORT = 502
_CONNECT_TIMEOUT_S = 3.0
_READ_TIMEOUT_S = 3.0


@dataclass(frozen=True)
class ModbusScanResult:
    """Outcome of probing one Modbus/TCP target."""

    host: str
    port: int
    reachable: bool
    unauth_read_coils: bool  # 0x01 succeeded without auth
    unauth_read_holding: bool  # 0x03 succeeded without auth
    device_identification: dict[str, str] = field(default_factory=dict)
    response_unit_ids: tuple[int, ...] = field(default_factory=tuple)
    write_attempt: bool = False  # True only when caller opted in
    write_succeeded: bool | None = None  # None when not attempted
    error: str = ""

    @property
    def has_unauth_exposure(self) -> bool:
        """Any anonymous read counts as an exposure for IEC 62443 SR 1.1."""
        return self.unauth_read_coils or self.unauth_read_holding


def _build_request(
    transaction_id: int,
    unit_id: int,
    pdu: bytes,
) -> bytes:
    """Build a Modbus/TCP frame: MBAP + PDU."""
    length = len(pdu) + 1  # +1 for the unit_id byte
    return struct.pack(_MBAP_FMT, transaction_id, 0x0000, length, unit_id) + pdu


def _parse_mbap(raw: bytes) -> tuple[int, int, int, int] | None:
    """Parse the 7-byte MBAP header. Returns None on truncation/garbage."""
    if len(raw) < 7:
        return None
    try:
        return struct.unpack(_MBAP_FMT, raw[:7])
    except struct.error:
        return None


def _send_recv(host: str, port: int, request: bytes) -> bytes:
    """Open a TCP socket, send `request`, read reply (up to 260 bytes —
    Modbus PDU max is 253 + 7 MBAP). Closes the socket cleanly. Raises
    OSError / socket.timeout — caller wraps."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(_CONNECT_TIMEOUT_S)
        sock.connect((host, port))
        sock.settimeout(_READ_TIMEOUT_S)
        sock.sendall(request)

        import time as _time
        buffer = b""
        # Best-effort drain — Modbus replies are bounded so we don't
        # need a streaming parser, just a single recv with the cap.
        # R2 — total-read deadline (anti-slowloris): a peer dribbling one byte before
        # each recv timeout could otherwise hold this loop for 260 x _READ_TIMEOUT_S.
        _read_end = _time.monotonic() + (_READ_TIMEOUT_S * 2)
        while len(buffer) < 260:
            if _time.monotonic() >= _read_end:
                break
            chunk = sock.recv(260 - len(buffer))
            if not chunk:
                break
            buffer += chunk
            # Stop early if the MBAP `length` field tells us we have it all.
            mbap = _parse_mbap(buffer)
            if mbap is not None:
                _, _, declared_length, _ = mbap
                # 6 = bytes of MBAP after `length` field (length is inclusive of
                # unit_id byte but starts AFTER the length field itself).
                if len(buffer) >= 6 + declared_length:
                    break
        return buffer


def _probe_read_coils(host: str, port: int, unit_id: int) -> tuple[bool, bytes]:
    """Function 0x01 — Read Coils, address 0, qty 1.

    Returns (ok, raw_response). `ok=True` means the device replied with a
    well-formed READ COILS response (function 0x01, not exception 0x81).

    MBAP layout: T(2) P(2) L(2) U(1) F(1) ... — function code at offset 7.
    """
    pdu = struct.pack(">BHH", 0x01, 0x0000, 0x0001)
    req = _build_request(transaction_id=0x0001, unit_id=unit_id, pdu=pdu)
    try:
        resp = _send_recv(host, port, req)
    except (TimeoutError, OSError):
        return False, b""
    mbap = _parse_mbap(resp)
    if mbap is None or len(resp) < 8:
        return False, resp
    function_code = resp[7]
    return function_code == 0x01, resp


def _probe_read_holding(host: str, port: int, unit_id: int) -> tuple[bool, bytes]:
    """Function 0x03 — Read Holding Registers, address 0, qty 1."""
    pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)
    req = _build_request(transaction_id=0x0002, unit_id=unit_id, pdu=pdu)
    try:
        resp = _send_recv(host, port, req)
    except (TimeoutError, OSError):
        return False, b""
    mbap = _parse_mbap(resp)
    if mbap is None or len(resp) < 8:
        return False, resp
    function_code = resp[7]
    return function_code == 0x03, resp


def _probe_device_identification(host: str, port: int, unit_id: int) -> dict[str, str]:
    """Function 0x2B / MEI 0x0E — Read Device Identification.

    Tries 'basic' object range (vendor name, product code, revision).
    Returns mapping {object_id_int: ascii_string}, possibly empty when
    the device doesn't support MEI 14 (older PLCs) or rejects with
    exception 0xAB.
    """
    # MEI Type 0x0E, Read Device ID code 0x01 (basic), Object Id 0x00.
    pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
    req = _build_request(transaction_id=0x0003, unit_id=unit_id, pdu=pdu)
    try:
        resp = _send_recv(host, port, req)
    except (TimeoutError, OSError):
        return {}
    if len(resp) < 12 or resp[7] != 0x2B:
        return {}

    # Layout starting at function code (offset 7): F(1) MEI(1) RDIcode(1)
    # Conformity(1) More(1) NextObj(1) NumObjects(1) Objects[].
    # NumObjects is at offset 13.
    n_objects = resp[13]
    cursor = 14
    out: dict[str, str] = {}
    object_names = {0: "vendor", 1: "product_code", 2: "revision"}
    for _ in range(n_objects):
        if cursor + 2 > len(resp):
            break
        obj_id = resp[cursor]
        obj_len = resp[cursor + 1]
        cursor += 2
        if cursor + obj_len > len(resp):
            break
        obj_value = resp[cursor : cursor + obj_len].decode("ascii", errors="replace")
        out[object_names.get(obj_id, f"object_{obj_id}")] = obj_value
        cursor += obj_len
    return out


def _ot_write_allowed() -> bool:
    """Double-gate for OT write operations: both KRYON_RED_TEAM and
    KRYON_OT_WRITE_FIRE must be set. Writing to a PLC is the single most dangerous
    action in the repo, so it is never enabled by a kwarg/default alone."""
    from kryon.util.env import env_bool, is_red_team  # noqa: PLC0415

    return is_red_team() and env_bool("KRYON_OT_WRITE_FIRE")


def modbus_scan(
    host: str,
    *,
    port: int = MODBUS_TCP_PORT,
    unit_id: int = 1,
    attempt_write: bool = False,
) -> ModbusScanResult:
    """Probe a target for Modbus/TCP exposure (IEC 62443 SR 1.1).

    Args:
        host: target IP / hostname.
        port: 502 by default; some integrators move it.
        unit_id: slave address (1 is the most common default).
        attempt_write: when True, send a Write Single Coil (0x05) probe.
            DANGEROUS — never leave this on in production audits without
            an explicit authorization clause in the engagement letter.

    Returns:
        ModbusScanResult — frozen, safe to log/serialize.
    """
    # Step 1 — TCP reachability.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(_CONNECT_TIMEOUT_S)
            s.connect((host, port))
    except (TimeoutError, OSError) as e:
        return ModbusScanResult(
            host=host,
            port=port,
            reachable=False,
            unauth_read_coils=False,
            unauth_read_holding=False,
            error=f"tcp_connect_failed: {type(e).__name__}",
        )

    # Step 2 — anonymous read probes.
    coils_ok, _ = _probe_read_coils(host, port, unit_id)
    holding_ok, _ = _probe_read_holding(host, port, unit_id)

    # Step 3 — device identification (best-effort, optional).
    device = _probe_device_identification(host, port, unit_id)

    # Step 4 — write probe (DOUBLE-GATED). Writing a coil can physically actuate
    # equipment, so the function never trusts the kwarg alone: even with
    # attempt_write=True it requires the explicit KRYON_RED_TEAM + KRYON_OT_WRITE_FIRE
    # double-gate (defence in depth — the most dangerous OT op must not depend on a
    # default). If the gate is closed, the write is skipped and reported as not attempted.
    write_attempted = attempt_write and _ot_write_allowed()
    write_ok: bool | None = None
    if write_attempted:
        # Address 9999 is rarely a real coil — avoids accidentally
        # actuating a real-world relay if the caller misconfigured.
        # 0x0000 OFF (anything non-zero would be ON).
        pdu = struct.pack(">BHH", 0x05, 0x270F, 0x0000)
        req = _build_request(transaction_id=0x0004, unit_id=unit_id, pdu=pdu)
        try:
            resp = _send_recv(host, port, req)
            write_ok = len(resp) >= 8 and resp[7] == 0x05
        except (TimeoutError, OSError):
            write_ok = False

    return ModbusScanResult(
        host=host,
        port=port,
        reachable=True,
        unauth_read_coils=coils_ok,
        unauth_read_holding=holding_ok,
        device_identification=device,
        response_unit_ids=(unit_id,) if (coils_ok or holding_ok) else (),
        write_attempt=write_attempted,
        write_succeeded=write_ok,
    )
