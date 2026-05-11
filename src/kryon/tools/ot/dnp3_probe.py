"""F84.2 — DNP3 (Distributed Network Protocol v3) audit tool.

DNP3 is the dominant SCADA protocol for power utilities in LATAM (ANDE
Paraguay, Itaipú, ENDE Bolivia, ENDESA Chile, Edesur Argentina). It
runs over TCP or UDP port 20000. Like Modbus, the BASE protocol has no
authentication; "Secure Authentication v5" (DNP3-SAv5) was added in
2011 but real deployments rarely enable it (interop pain with legacy
RTUs from the 80s/90s).

This module probes a target with raw socket — no `pydnp3` dependency.
We send a DNP3 Data Link Frame containing a Read request (function 0x01)
for Class 0 data (object 60, variation 1) and parse the IIN bits in the
response to confirm the device is authoritative.

Frame layout (per IEEE 1815):
  Data Link Layer header (10 bytes):
    Start Bytes      : 0x05 0x64
    Length           : 1 byte  — bytes following except CRC
    Control          : 1 byte  — direction, primary, function code
    Destination Addr : 2 bytes LE
    Source Addr      : 2 bytes LE
    CRC              : 2 bytes LE  — over the 8 bytes above
  Transport Layer header (1 byte): FIR | FIN | sequence
  Application Layer:
    App Control      : 1 byte
    Function Code    : 1 byte (0x01 Read, 0x02 Write, 0x05 Direct Operate, …)
    Object Header    : 4 bytes (group | variation | qualifier | range)

References:
  - IEEE 1815-2012 Standard for Electric Power Systems Communications
  - DNP3 SAv5 (Secure Authentication v5)
  - IEC 62443-3-3 SR 1.1, SR 5.1
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

DNP3_DEFAULT_PORT = 20000
_CONNECT_TIMEOUT_S = 3.0
_READ_TIMEOUT_S = 3.0

# Standard DNP3 broadcast addresses (free for engineering tools).
_DEFAULT_SOURCE = 1
_DEFAULT_DEST = 4  # Common outstation default; integrator may have changed it.


@dataclass(frozen=True)
class DNP3ProbeResult:
    """Outcome of probing one DNP3 target."""

    host: str
    port: int
    reachable: bool
    responds_to_dnp3: bool  # device replied with valid DNP3 framing
    iin_bits: dict[str, bool] = field(default_factory=dict)  # device flags
    outstation_address: int | None = None
    secure_auth_v5_active: bool | None = None  # None if undetermined
    error: str = ""

    @property
    def has_unauth_exposure(self) -> bool:
        """If the device responded to a Read without challenging us for
        SAv5 credentials, anyone with TCP/20000 reachability can read."""
        return self.responds_to_dnp3 and not (self.secure_auth_v5_active or False)


# ---------- CRC-16 / DNP per IEEE 1815 ----------
# Polynomial 0x3D65, initial value 0x0000, reflected.
_CRC_POLY = 0xA6BC  # bit-reflected 0x3D65
_CRC_TABLE: list[int] | None = None


def _build_crc_table() -> list[int]:
    table: list[int] = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC_POLY
            else:
                crc >>= 1
        table.append(crc)
    return table


def _dnp3_crc(payload: bytes) -> int:
    global _CRC_TABLE
    if _CRC_TABLE is None:
        _CRC_TABLE = _build_crc_table()
    crc = 0
    for b in payload:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF


# ---------- Frame construction ----------


def _build_read_class0_frame(
    *,
    source: int = _DEFAULT_SOURCE,
    destination: int = _DEFAULT_DEST,
) -> bytes:
    """Build a complete DNP3 frame asking the outstation for Class 0 data
    (object group 60, variation 1, qualifier 0x06 = no range).
    """
    # Application Layer payload: AppCtrl(1) | FuncCode(1) | Obj(2) | Qual(1)
    # Qualifier 0x06 means "no index, no range" — read all of class 0.
    app_layer = struct.pack(">BBBBBB", 0xC0, 0x01, 0x3C, 0x01, 0x06, 0x00)
    # Transport Layer: FIR=1 FIN=1 seq=0
    transport = struct.pack(">B", 0xC0)
    user_data = transport + app_layer

    # Data Link header. Length is "bytes following the length field
    # except the CRCs of the user data" — for a frame with N user bytes
    # (transport + app), length = 5 + N (CTRL + DST + SRC = 5 bytes)
    # but per spec it's actually 5 + len(user_data) capped at 255.
    length = 5 + len(user_data)
    # Control byte 0xC4 = DIR(1) PRM(1) FCB(0) FCV(0) FuncCode(0100=4 Unconfirmed user data)
    control = 0xC4

    dl_header_no_crc = struct.pack(
        "<BBBBHH",
        0x05,
        0x64,
        length,
        control,
        destination,
        source,
    )
    dl_crc = _dnp3_crc(dl_header_no_crc)
    dl_frame = dl_header_no_crc + struct.pack("<H", dl_crc)

    # User data must be split into 16-byte blocks each with its own CRC.
    # For our small request it fits in one block.
    user_with_crc = user_data + struct.pack("<H", _dnp3_crc(user_data))

    return dl_frame + user_with_crc


# ---------- Response parsing ----------


def _parse_iin(response: bytes) -> dict[str, bool] | None:
    """Pull the 16-bit IIN word from an outstation response.

    Layout: DL header (10 bytes) | transport (1) | app ctrl (1) | func (1)
    | IIN1 (1) | IIN2 (1) | objects...
    IIN starts at offset 13.
    """
    if len(response) < 15:
        return None
    if response[0] != 0x05 or response[1] != 0x64:
        return None
    # Skip the CRC after the DL header by reading at fixed offsets.
    iin1 = response[13]
    iin2 = response[14]
    return {
        "broadcast": bool(iin1 & 0x01),
        "class_1_events": bool(iin1 & 0x02),
        "class_2_events": bool(iin1 & 0x04),
        "class_3_events": bool(iin1 & 0x08),
        "need_time": bool(iin1 & 0x10),
        "local_control": bool(iin1 & 0x20),
        "device_trouble": bool(iin1 & 0x40),
        "device_restart": bool(iin1 & 0x80),
        "no_func_code_supp": bool(iin2 & 0x01),
        "object_unknown": bool(iin2 & 0x02),
        "parameter_error": bool(iin2 & 0x04),
        "buffer_overflow": bool(iin2 & 0x08),
        "operation_already_executing": bool(iin2 & 0x10),
        "config_corrupt": bool(iin2 & 0x20),
    }


def _parse_outstation_address(response: bytes) -> int | None:
    """Extract the responder's source address from the DL header.

    DL header layout: start(2) length(1) control(1) dest(2) source(2) crc(2).
    Source is at offset 6-7 (LE uint16).
    """
    if len(response) < 10:
        return None
    if response[0] != 0x05 or response[1] != 0x64:
        return None
    return struct.unpack_from("<H", response, 6)[0]


def _detect_sav5(response: bytes) -> bool | None:
    """Heuristic: a SAv5-protected device challenges with an Authentication
    Response (function code 0x83) carrying object 120 (Authentication
    Challenge). Plain Read response uses function code 0x81.

    Returns:
        True   — challenged for credentials (SAv5 active)
        False  — replied with Read response (no SAv5)
        None   — frame too short to tell
    """
    if len(response) < 13:
        return None
    if response[0] != 0x05 or response[1] != 0x64:
        return None
    func_code = response[12]
    if func_code == 0x83:
        return True
    if func_code == 0x81:
        return False
    return None


# ---------- Socket I/O (mirrors modbus_scan style) ----------


def _send_recv(host: str, port: int, request: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(_CONNECT_TIMEOUT_S)
        sock.connect((host, port))
        sock.settimeout(_READ_TIMEOUT_S)
        sock.sendall(request)
        # DNP3 frames cap at ~292 bytes (255 length + headers).
        buffer = b""
        while len(buffer) < 300:
            chunk = sock.recv(300 - len(buffer))
            if not chunk:
                break
            buffer += chunk
        return buffer


# ---------- Public API ----------


def dnp3_probe(
    host: str,
    *,
    port: int = DNP3_DEFAULT_PORT,
    source: int = _DEFAULT_SOURCE,
    destination: int = _DEFAULT_DEST,
) -> DNP3ProbeResult:
    """Probe a target for DNP3 exposure (IEC 62443 SR 1.1, NERC CIP-005).

    Sends a single Read Class 0 request and inspects the response. No
    write probes — DNP3 has function codes (0x05 Direct Operate, 0x06
    Select-Before-Operate) that physically actuate breakers and switches.
    Writing is OUT OF SCOPE for the audit baseline; doing so without
    operator authorization can trip a substation.
    """
    # Step 1 — TCP reachability.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(_CONNECT_TIMEOUT_S)
            s.connect((host, port))
    except (TimeoutError, OSError) as e:
        return DNP3ProbeResult(
            host=host,
            port=port,
            reachable=False,
            responds_to_dnp3=False,
            error=f"tcp_connect_failed: {type(e).__name__}",
        )

    # Step 2 — send Read Class 0 frame.
    frame = _build_read_class0_frame(source=source, destination=destination)
    try:
        response = _send_recv(host, port, frame)
    except (TimeoutError, OSError) as e:
        return DNP3ProbeResult(
            host=host,
            port=port,
            reachable=True,
            responds_to_dnp3=False,
            error=f"dnp3_read_failed: {type(e).__name__}",
        )

    if not response or response[:2] != b"\x05\x64":
        return DNP3ProbeResult(
            host=host,
            port=port,
            reachable=True,
            responds_to_dnp3=False,
        )

    iin = _parse_iin(response) or {}
    addr = _parse_outstation_address(response)
    sav5 = _detect_sav5(response)

    return DNP3ProbeResult(
        host=host,
        port=port,
        reachable=True,
        responds_to_dnp3=True,
        iin_bits=iin,
        outstation_address=addr,
        secure_auth_v5_active=sav5,
    )
