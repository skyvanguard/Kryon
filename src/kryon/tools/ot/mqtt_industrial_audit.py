"""F84.5 — MQTT industrial broker audit tool.

MQTT is the dominant IIoT message-bus protocol — used by SCADA brokers
(Mosquitto, HiveMQ, RabbitMQ MQTT plugin, EMQX), industrial gateways
(Siemens IOT2050, Schneider Modicon Edge), and increasingly by
banking-adjacent IoT (datacenter sensors, generator telemetry).
Common defaults expose two layers of attack surface:

  1. Anonymous CONNECT accepted (auth disabled in mosquitto.conf)
  2. `$SYS/#` topic readable → broker version, uptime, clients, msgs/sec
  3. Wildcard subscription `#` enumerates every business topic,
     potentially including command channels for connected devices

This tool probes the first two cheaply (CONNECT + small SUBSCRIBE).
The wildcard `#` enumeration is intentionally NOT automated — it can
flood a production broker. The playbook calls it out as a manual
follow-up on findings.

Frame format (MQTT v3.1.1, simplest case):
  CONNECT (type 0x10):
    fixed header: 0x10 | remaining_length (var-int)
    var header  : proto_name_len(2) | "MQTT" | proto_level(1)=0x04
                  | flags(1)=0x02 (clean session) | keepalive(2)=0x003C
    payload     : client_id_len(2) | client_id (ASCII)

  CONNACK (type 0x20):
    fixed header: 0x20 | 0x02
    var header  : flags(1) | return_code(1)
       return_code: 0=accepted, 1-5=rejected with reason

References:
  - MQTT v3.1.1 OASIS Standard (2014-10)
  - OWASP IoT Top 10 (I1: Weak passwords; I3: Insecure interfaces)
  - IEC 62443-3-3 SR 1.1
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

MQTT_DEFAULT_PORT = 1883
_CONNECT_TIMEOUT_S = 3.0
_READ_TIMEOUT_S = 3.0


@dataclass(frozen=True)
class MqttProbeResult:
    """Outcome of probing one MQTT broker."""

    host: str
    port: int
    reachable: bool
    anonymous_connect_accepted: bool
    sys_topic_readable: bool         # $SYS/# subscription got data
    broker_banner: str = ""          # populated when $SYS leaks ver/info
    connack_return_code: int | None = None
    error: str = ""

    @property
    def has_unauth_exposure(self) -> bool:
        """Anonymous CONNECT alone is the layer-7 finding."""
        return self.anonymous_connect_accepted


# ---------- Var-int (MQTT remaining length encoding) ----------


def _encode_remaining_length(length: int) -> bytes:
    """MQTT uses 7-bit-per-byte var-int with 0x80 continuation flag."""
    if length < 0 or length >= 268_435_456:
        raise ValueError("remaining length out of range")
    out = bytearray()
    while True:
        byte = length & 0x7F
        length >>= 7
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            break
    return bytes(out)


def _decode_remaining_length(data: bytes, start: int = 1) -> tuple[int, int]:
    """Returns (length, bytes_consumed). Raises on malformed input."""
    multiplier = 1
    length = 0
    cursor = start
    while True:
        if cursor >= len(data):
            raise ValueError("truncated var-int")
        byte = data[cursor]
        length += (byte & 0x7F) * multiplier
        cursor += 1
        if not byte & 0x80:
            break
        multiplier *= 128
        if multiplier > 128 ** 3:
            raise ValueError("var-int too long")
    return length, cursor


# ---------- Frame builders ----------


def _build_connect(client_id: str = "kryon-bench") -> bytes:
    """Anonymous CONNECT (no username / password) for MQTT v3.1.1."""
    proto_name = b"MQTT"
    proto_level = 0x04                # MQTT 3.1.1
    flags = 0x02                      # clean session, no will, no auth
    keepalive = 60
    cid_bytes = client_id.encode("utf-8")

    var_header = (
        struct.pack(">H", len(proto_name)) + proto_name
        + struct.pack(">BBH", proto_level, flags, keepalive)
    )
    payload = struct.pack(">H", len(cid_bytes)) + cid_bytes
    body = var_header + payload

    fixed_header = bytes([0x10]) + _encode_remaining_length(len(body))
    return fixed_header + body


def _build_subscribe(packet_id: int, topic: str) -> bytes:
    """SUBSCRIBE packet for a single topic at QoS 0."""
    topic_bytes = topic.encode("utf-8")
    payload = (
        struct.pack(">H", len(topic_bytes)) + topic_bytes
        + bytes([0x00])  # QoS 0
    )
    var_header = struct.pack(">H", packet_id)
    body = var_header + payload

    # Type 0x82 = SUBSCRIBE with required reserved bits = 0x02
    fixed_header = bytes([0x82]) + _encode_remaining_length(len(body))
    return fixed_header + body


def _build_disconnect() -> bytes:
    """DISCONNECT packet — clean session close."""
    return bytes([0xE0, 0x00])


# ---------- Response parsers ----------


def _parse_connack(data: bytes) -> int | None:
    """Return CONNACK return code (0=accepted) or None if malformed."""
    if len(data) < 4:
        return None
    if data[0] != 0x20:
        return None
    # Fixed header: type 0x20 | remaining_length 0x02
    # Var header: flags(1) | return_code(1)
    return data[3]


def _parse_publish_topic_payload(data: bytes) -> tuple[str, bytes] | None:
    """Best-effort PUBLISH parser: returns (topic, payload) or None.

    Layout (QoS 0):
      fixed: 0x30 | remaining_length
      var  : topic_len(2) | topic | payload (rest)
    """
    if len(data) < 4 or data[0] & 0xF0 != 0x30:
        return None
    try:
        rem_len, body_start = _decode_remaining_length(data, start=1)
    except ValueError:
        return None
    if body_start + rem_len > len(data):
        return None
    body = data[body_start:body_start + rem_len]
    if len(body) < 2:
        return None
    topic_len = struct.unpack(">H", body[:2])[0]
    if 2 + topic_len > len(body):
        return None
    topic = body[2:2 + topic_len].decode("utf-8", errors="replace")
    payload = body[2 + topic_len:]
    return topic, payload


# ---------- Socket I/O ----------


def _send_recv(sock: socket.socket, data: bytes, want_bytes: int = 256) -> bytes:
    sock.settimeout(_READ_TIMEOUT_S)
    sock.sendall(data)
    buffer = b""
    while len(buffer) < want_bytes:
        chunk = sock.recv(want_bytes - len(buffer))
        if not chunk:
            break
        buffer += chunk
    return buffer


def _drain_publishes(sock: socket.socket, timeout_s: float = 1.0) -> list[bytes]:
    """Read whatever PUBLISHes the broker pushes within the timeout."""
    sock.settimeout(timeout_s)
    frames: list[bytes] = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            frames.append(chunk)
    except (socket.timeout, OSError):
        pass
    return frames


# ---------- Public API ----------


def mqtt_industrial_audit(
    host: str,
    *,
    port: int = MQTT_DEFAULT_PORT,
) -> MqttProbeResult:
    """Probe an MQTT broker for two industrial-relevant exposures:
    anonymous CONNECT accepted, and `$SYS/#` readable.

    Read-only; never PUBLISHes anything to the broker.
    """
    # Step 1 — TCP reachability.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_CONNECT_TIMEOUT_S)
        sock.connect((host, port))
    except (OSError, socket.timeout) as e:
        return MqttProbeResult(
            host=host,
            port=port,
            reachable=False,
            anonymous_connect_accepted=False,
            sys_topic_readable=False,
            error=f"tcp_connect_failed: {type(e).__name__}",
        )

    try:
        # Step 2 — anonymous CONNECT.
        try:
            connack = _send_recv(sock, _build_connect(), want_bytes=4)
        except (OSError, socket.timeout) as e:
            return MqttProbeResult(
                host=host,
                port=port,
                reachable=True,
                anonymous_connect_accepted=False,
                sys_topic_readable=False,
                error=f"connect_send_failed: {type(e).__name__}",
            )

        rc = _parse_connack(connack)
        if rc is None or rc != 0:
            return MqttProbeResult(
                host=host,
                port=port,
                reachable=True,
                anonymous_connect_accepted=False,
                sys_topic_readable=False,
                connack_return_code=rc,
            )

        # Step 3 — SUBSCRIBE $SYS/# and drain PUBLISHes briefly.
        sys_readable = False
        broker_banner = ""
        try:
            sock.sendall(_build_subscribe(packet_id=1, topic="$SYS/#"))
            frames = _drain_publishes(sock, timeout_s=1.5)
            for raw in frames:
                cursor = 0
                while cursor < len(raw):
                    parsed = _parse_publish_topic_payload(raw[cursor:])
                    if parsed is None:
                        break
                    topic, payload = parsed
                    if topic.startswith("$SYS/"):
                        sys_readable = True
                        # Pull broker version / build / uptime when present.
                        try:
                            text = payload.decode("utf-8", errors="replace")[:96]
                        except Exception:
                            text = ""
                        if "/version" in topic and not broker_banner:
                            broker_banner = text
                        elif not broker_banner and text:
                            broker_banner = f"{topic}={text}"
                    # Move cursor past this PUBLISH frame.
                    rem_len, body_start = _decode_remaining_length(raw[cursor:], start=1)
                    cursor += body_start + rem_len
        except (OSError, socket.timeout, ValueError):
            # Drain failures don't undo the CONNECT finding.
            pass

        # Clean disconnect.
        try:
            sock.sendall(_build_disconnect())
        except OSError:
            pass

        return MqttProbeResult(
            host=host,
            port=port,
            reachable=True,
            anonymous_connect_accepted=True,
            sys_topic_readable=sys_readable,
            broker_banner=broker_banner,
            connack_return_code=0,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass
