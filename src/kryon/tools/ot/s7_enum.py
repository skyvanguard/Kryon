"""F84.3 — Siemens S7Comm enumeration tool.

Siemens PLCs (S7-300, S7-400, S7-1200, S7-1500) speak S7Comm over
ISO-on-TCP (RFC 1006) on port 102/tcp. The protocol has zero
authentication in its base form. S7Comm-Plus (S7-1500 from firmware
v2.x) added security blocks but most LATAM industrial deployments —
banking HVAC, building automation, generator monitoring — still run
plain S7Comm because of legacy interop with WinCC/STEP7.

This module probes a target through the canonical 3-stage handshake:

  1. TCP connect to 102/tcp
  2. COTP Connection Request → device replies Connection Confirm
  3. S7 Setup Communication → device replies Setup Ack
  4. (optional) S7 Read SZL ID 0x0011 → returns module identification

We treat ANY successful Setup Ack as proof of "anonymous S7Comm
session established", which violates IEC 62443 SR 1.1 by definition.
The SZL probe is informational fingerprint, not a control finding.

Frame layout (simplified):
  TPKT header  : ver(1) reserved(1) length(2)              = 4 bytes
  COTP header  : length(1) PDU type(1) ...                 = variable
  S7 PDU       : proto_id(1) ROSCTR(1) reserved(2)
                 PDU ref(2) param_len(2) data_len(2)
                 [error class(1) error code(1) on response]
                 + parameters + data

References:
  - Wireshark s7comm.c dissector (canonical reference)
  - Siemens S7-1500 manual 6ES7515-2AM02-0AB0 (security advisory)
  - IEC 62443-3-3 SR 1.1, SR 1.5
  - https://github.com/digitalbond/Redpoint nse scripts
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

S7COMM_DEFAULT_PORT = 102
_CONNECT_TIMEOUT_S = 3.0
_READ_TIMEOUT_S = 5.0  # Some PLCs are slow to ack Setup Communication.


@dataclass(frozen=True)
class S7EnumResult:
    """Outcome of probing one S7Comm target."""

    host: str
    port: int
    reachable: bool
    cotp_connected: bool  # COTP Connection Confirm received
    s7_session_established: bool  # S7 Setup Ack received
    module_identification: dict[str, str] = field(default_factory=dict)
    plc_firmware_version: str = ""
    error: str = ""

    @property
    def has_unauth_exposure(self) -> bool:
        """Anonymous S7 session established without challenge = exposure."""
        return self.s7_session_established


# ---------- TPKT + COTP framing ----------


def _tpkt_wrap(payload: bytes) -> bytes:
    """RFC 1006 TPKT header: version 3, reserved 0, total length BE."""
    total_length = 4 + len(payload)
    return struct.pack(">BBH", 0x03, 0x00, total_length) + payload


def _build_cotp_connection_request(
    *,
    src_tsap: int = 0x0100,
    dst_tsap: int = 0x0102,  # Slot 2, common S7-300/400 default
) -> bytes:
    """COTP CR PDU: classic Connection Request with Class 0 + parameter
    blocks for source/dest TSAP. The TSAP encodes (rack, slot) for the
    Siemens PLC. dst_tsap=0x0102 = rack 0 slot 2 (CPU slot for legacy);
    S7-1200/1500 typically use 0x0200 (rack 0 slot 0)."""
    # COTP header (variable):
    #  Length (1) | PDU code 0xE0 (CR) | DST_REF(2)=0 | SRC_REF(2)=1
    #  | Class 0+Option 0 (1)
    # TSAP parameters (3 bytes header each + data):
    #  Type 0xC1 (calling TSAP) len 2 | data 2 bytes
    #  Type 0xC2 (called TSAP)  len 2 | data 2 bytes
    #  Type 0xC0 (TPDU size)    len 1 | data = 0x0A (1024 bytes)
    cotp = struct.pack(">BBHHB", 0x11, 0xE0, 0x0000, 0x0001, 0x00)
    cotp += struct.pack(">BBH", 0xC1, 0x02, src_tsap)
    cotp += struct.pack(">BBH", 0xC2, 0x02, dst_tsap)
    cotp += struct.pack(">BBB", 0xC0, 0x01, 0x0A)
    return _tpkt_wrap(cotp)


def _is_cotp_connection_confirm(response: bytes) -> bool:
    """Inspect TPKT+COTP shape: TPKT(4) + COTP_LEN(1) + 0xD0 (CC PDU)."""
    if len(response) < 6:
        return False
    if response[0] != 0x03 or response[1] != 0x00:
        return False  # not TPKT
    return response[5] == 0xD0  # COTP Connection Confirm


def _build_s7_setup_communication() -> bytes:
    """S7 Setup Communication request — establishes session params (max
    AMQ called/calling, max PDU length).

    Layout after TPKT+COTP_data (TPKT(4) + COTP(3 bytes for Data PDU)):
      proto_id(1)=0x32 | ROSCTR(1)=1 (Job) | reserved(2)=0
      | PDU_ref(2)=0x0000 | param_len(2)=8 | data_len(2)=0
      | params: setup-comm code 0xF0 + reserved 0x00 + max_amq_calling(2)
                + max_amq_called(2) + pdu_size(2)
    """
    s7_pdu = struct.pack(
        ">BBHHHH",
        0x32,
        0x01,
        0x0000,
        0x0000,
        0x0008,
        0x0000,
    )
    s7_pdu += struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x03C0)
    # COTP Data PDU header: length(1)=0x02 | PDU_code(1)=0xF0 | TPDU_nr(1)
    cotp = struct.pack(">BBB", 0x02, 0xF0, 0x80) + s7_pdu
    return _tpkt_wrap(cotp)


def _is_s7_setup_ack(response: bytes) -> bool:
    """Setup Ack: ROSCTR=3 (Ack-Data) at offset TPKT(4)+COTP(3)+1 = 8.

    Layout from offset 7: proto_id(0x32) | ROSCTR (3 = Ack with data).
    Older PLCs may also reply with ROSCTR=2 (Ack only).
    """
    if len(response) < 9:
        return False
    if response[0] != 0x03 or response[1] != 0x00:
        return False
    if response[7] != 0x32:  # not S7 protocol id
        return False
    rosctr = response[8]
    return rosctr in (0x02, 0x03)


def _build_s7_read_szl(szl_id: int = 0x0011, szl_index: int = 0x0000) -> bytes:
    """S7 User-Data request reading SZL (System Status List).

    SZL 0x0011 = "Module identification": vendor name, order code,
    firmware revision, etc. SZL 0x001C = "Component identification":
    PLC name and plant designator.
    """
    # User Data parameter:
    #  param_head(3) = 0x000112
    #  param_len(1) = 0x04 (length of next 4 bytes)
    #  method(1) = 0x11 (request)
    #  type(1) = 0x44 | sub-func(1)= 0x01 (read SZL)
    #  seq(1) = 0
    # Then data block:
    #  retval(1)=0xff | data_type(1)=0x09 | length(2)
    #  | szl_id(2) | szl_index(2)
    s7_pdu = struct.pack(
        ">BBHHHH",
        0x32,
        0x07,
        0x0000,
        0x0001,
        0x0008,
        0x0008,  # ROSCTR=7 (User Data)
    )
    s7_pdu += struct.pack(">BBBBBBBB", 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00)
    s7_pdu += struct.pack(">BBHHH", 0xFF, 0x09, 0x0004, szl_id, szl_index)
    cotp = struct.pack(">BBB", 0x02, 0xF0, 0x80) + s7_pdu
    return _tpkt_wrap(cotp)


def _parse_szl_module_id(response: bytes) -> dict[str, str]:
    """Pull ASCII fields from a SZL 0x0011 response payload.

    The SZL data starts after the User-Data return-value block; the
    parser is conservative — extract any ASCII string of length ≥ 6
    that's printable. Real Siemens responses contain things like
    `6ES7 ...` (order code) and `V 4.1.0` (firmware).
    """
    out: dict[str, str] = {}
    if len(response) < 30:
        return out

    # Heuristic — scan for printable ASCII runs ≥ 6 chars.
    # Production parser (future Sprint) would parse the SZL data record
    # field-by-field per Siemens manual.
    runs: list[str] = []
    current = bytearray()
    for byte in response[20:]:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= 6:
                runs.append(current.decode("ascii", errors="replace").strip())
            current = bytearray()
    if len(current) >= 6:
        runs.append(current.decode("ascii", errors="replace").strip())

    # First run is usually the order code (6ES7...), second the
    # MLFB / firmware string. Limit to 4 to avoid noise.
    for i, run in enumerate(runs[:4]):
        out[f"szl_field_{i}"] = run

    # Common Siemens order codes start with "6ES7" or "6AG1".
    for run in runs:
        if run.startswith(("6ES7", "6AG1", "6GK")):
            out["order_code"] = run
            break

    # Firmware version pattern: "V x.y.z".
    import re

    for run in runs:
        m = re.search(r"V\s*\d+\.\d+(\.\d+)?", run)
        if m:
            out["firmware"] = m.group(0).strip()
            break

    return out


# ---------- Socket I/O ----------


def _send_recv(sock: socket.socket, data: bytes) -> bytes:
    """Send + read on an already-open socket."""
    sock.settimeout(_READ_TIMEOUT_S)
    sock.sendall(data)
    buffer = b""
    while len(buffer) < 1024:
        chunk = sock.recv(1024 - len(buffer))
        if not chunk:
            break
        buffer += chunk
        # If we have a TPKT header, check if we got the full frame.
        if len(buffer) >= 4 and buffer[0] == 0x03:
            declared = struct.unpack(">H", buffer[2:4])[0]
            if len(buffer) >= declared:
                break
    return buffer


# ---------- Public API ----------


def s7_enum(
    host: str,
    *,
    port: int = S7COMM_DEFAULT_PORT,
    rack: int = 0,
    slot: int = 2,
) -> S7EnumResult:
    """Enumerate Siemens S7Comm via the standard COTP+S7 handshake.

    Args:
        host: target IP/hostname.
        port: 102 by default.
        rack: 0 typical.
        slot: 2 for S7-300/400 CPU; use 0 or 1 for S7-1200/1500.
            (Probe could be made adaptive — Sprint 2 enhancement.)
    """
    dst_tsap = (0x01 << 8) | (rack * 0x20 + slot)

    # Step 1 — TCP reachability.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_CONNECT_TIMEOUT_S)
        sock.connect((host, port))
    except (TimeoutError, OSError) as e:
        return S7EnumResult(
            host=host,
            port=port,
            reachable=False,
            cotp_connected=False,
            s7_session_established=False,
            error=f"tcp_connect_failed: {type(e).__name__}",
        )

    try:
        # Step 2 — COTP Connection Request.
        cr = _build_cotp_connection_request(dst_tsap=dst_tsap)
        cr_resp = _send_recv(sock, cr)
        cotp_ok = _is_cotp_connection_confirm(cr_resp)
        if not cotp_ok:
            return S7EnumResult(
                host=host,
                port=port,
                reachable=True,
                cotp_connected=False,
                s7_session_established=False,
                error="cotp_connection_refused",
            )

        # Step 3 — S7 Setup Communication.
        setup = _build_s7_setup_communication()
        setup_resp = _send_recv(sock, setup)
        s7_ok = _is_s7_setup_ack(setup_resp)
        if not s7_ok:
            return S7EnumResult(
                host=host,
                port=port,
                reachable=True,
                cotp_connected=True,
                s7_session_established=False,
                error="s7_setup_rejected",
            )

        # Step 4 — SZL probe (best-effort).
        szl_req = _build_s7_read_szl(szl_id=0x0011)
        try:
            szl_resp = _send_recv(sock, szl_req)
            module_id = _parse_szl_module_id(szl_resp)
        except (TimeoutError, OSError):
            module_id = {}

        firmware = module_id.get("firmware", "")
        return S7EnumResult(
            host=host,
            port=port,
            reachable=True,
            cotp_connected=True,
            s7_session_established=True,
            module_identification=module_id,
            plc_firmware_version=firmware,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass
