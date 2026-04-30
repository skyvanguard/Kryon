"""F84.5 — tests for kryon.tools.ot.mqtt_industrial_audit."""

from __future__ import annotations

import socket
import struct
from typing import Iterator

import pytest


# ---------- MQTT frame helpers ----------


def _connack(return_code: int = 0) -> bytes:
    """CONNACK with given return code (0 = accepted)."""
    return bytes([0x20, 0x02, 0x00, return_code])


def _publish(topic: str, payload: bytes) -> bytes:
    """PUBLISH packet with QoS 0 (no packet id)."""
    topic_bytes = topic.encode("utf-8")
    body = struct.pack(">H", len(topic_bytes)) + topic_bytes + payload

    # remaining length encoder (var-int up to 127 here for tests).
    if len(body) < 128:
        rl = bytes([len(body)])
    else:
        rl = bytes([(len(body) & 0x7F) | 0x80, len(body) >> 7])
    return bytes([0x30]) + rl + body


# ---------- Mock socket ----------


class _MockSocket:
    """Replay queue. Each `sendall` advances to the next reply.
    `recv` may be called multiple times per reply; once drained, returns b"".
    Drain timeouts are simulated with `socket.timeout` after the reply
    is consumed."""

    def __init__(self, replies: list[bytes], drain_after: int | None = None) -> None:
        self._replies: Iterator[bytes] = iter(replies)
        self._buffer = b""
        self._sends_seen = 0
        self._drain_after = drain_after  # raise socket.timeout after N sends

    def settimeout(self, _t: float) -> None: pass
    def connect(self, _addr: tuple[str, int]) -> None: pass

    def sendall(self, _data: bytes) -> None:
        self._sends_seen += 1
        try:
            self._buffer = next(self._replies)
        except StopIteration:
            self._buffer = b""

    def recv(self, n: int) -> bytes:
        # If the drain semaphore is set and we've passed it, simulate timeout.
        if (self._drain_after is not None
                and self._sends_seen >= self._drain_after
                and not self._buffer):
            raise socket.timeout("simulated drain timeout")
        chunk = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return chunk

    def close(self) -> None: pass

    def __enter__(self) -> "_MockSocket": return self
    def __exit__(self, *exc: object) -> None: self.close()


@pytest.fixture
def patch_socket(monkeypatch: pytest.MonkeyPatch):
    def _install(replies: list[bytes], drain_after: int | None = None) -> _MockSocket:
        mock = _MockSocket(replies, drain_after=drain_after)
        monkeypatch.setattr(socket, "socket", lambda *a, **k: mock)
        return mock
    return _install


# ---------- Reachability ----------


class TestReachability:
    def test_unreachable_returns_error(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        class _Refused:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def settimeout(self, _t): pass
            def connect(self, _a): raise OSError("refused")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **k: _Refused())
        r = mqtt_industrial_audit("10.255.255.255")
        assert r.reachable is False
        assert "tcp_connect_failed" in r.error
        assert r.has_unauth_exposure is False


# ---------- CONNACK handling ----------


class TestConnack:
    def test_anonymous_connect_accepted(self, patch_socket) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        # 1st sendall = CONNECT → CONNACK rc=0; 2nd = SUBSCRIBE; rest drain.
        replies = [_connack(0), b""]
        patch_socket(replies, drain_after=2)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.reachable is True
        assert r.anonymous_connect_accepted is True
        assert r.connack_return_code == 0
        assert r.has_unauth_exposure is True

    def test_connect_rejected_with_rc5(self, patch_socket) -> None:
        """rc=5 = not authorized — broker requires creds."""
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        replies = [_connack(5)]
        patch_socket(replies)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.anonymous_connect_accepted is False
        assert r.connack_return_code == 5
        assert r.has_unauth_exposure is False

    def test_connect_rejected_with_rc4(self, patch_socket) -> None:
        """rc=4 = bad username/password."""
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        replies = [_connack(4)]
        patch_socket(replies)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.anonymous_connect_accepted is False

    def test_garbage_response_marks_no_connect(self, patch_socket) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        replies = [b"\x00\x01\x02\x03"]
        patch_socket(replies)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.anonymous_connect_accepted is False
        assert r.connack_return_code is None


# ---------- $SYS topic disclosure ----------


class TestSysTopic:
    def test_sys_topic_readable_with_version_banner(self, patch_socket) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        sys_pub = _publish("$SYS/broker/version", b"mosquitto version 2.0.18")
        # Replies in order: CONNACK accept, SUBSCRIBE drain (PUBLISH).
        # Only 2 sendalls before drain (CONNECT + SUBSCRIBE), then DISCONNECT (3rd).
        replies = [_connack(0), sys_pub]
        patch_socket(replies, drain_after=3)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.anonymous_connect_accepted is True
        assert r.sys_topic_readable is True
        assert "mosquitto" in r.broker_banner

    def test_sys_topic_silent_means_not_readable(self, patch_socket) -> None:
        """SUBSCRIBE went through but no PUBLISH frames came back —
        broker may have ACL'd the $SYS topic."""
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        replies = [_connack(0), b""]  # CONNACK then nothing
        patch_socket(replies, drain_after=2)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.anonymous_connect_accepted is True
        assert r.sys_topic_readable is False

    def test_sys_topic_with_non_version_topic_still_marks_readable(
        self, patch_socket,
    ) -> None:
        """Any $SYS PUBLISH counts — version is a bonus banner field."""
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        sys_pub = _publish("$SYS/broker/uptime", b"3600")
        replies = [_connack(0), sys_pub]
        patch_socket(replies, drain_after=3)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.sys_topic_readable is True
        # broker_banner gets the topic=value form when version isn't there.
        assert "uptime" in r.broker_banner

    def test_non_sys_publish_does_not_mark_sys_readable(
        self, patch_socket,
    ) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        normal_pub = _publish("sensors/temp", b"22.5")
        replies = [_connack(0), normal_pub]
        patch_socket(replies, drain_after=3)

        r = mqtt_industrial_audit("10.0.0.5")
        assert r.sys_topic_readable is False


# ---------- Var-int encoder/decoder ----------


class TestVarInt:
    def test_encode_below_128(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _encode_remaining_length

        assert _encode_remaining_length(0) == b"\x00"
        assert _encode_remaining_length(127) == b"\x7f"

    def test_encode_above_128_uses_continuation(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _encode_remaining_length

        # 128 = 0x80 0x01 (low 7 bits = 0, continuation, then 1)
        encoded = _encode_remaining_length(128)
        assert encoded[0] & 0x80
        assert encoded[1] == 0x01

    def test_decode_round_trip(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import (
            _decode_remaining_length,
            _encode_remaining_length,
        )

        for original in (0, 1, 127, 128, 16_383, 16_384, 200_000):
            encoded = _encode_remaining_length(original)
            decoded, _ = _decode_remaining_length(b"\xff" + encoded, start=1)
            assert decoded == original, f"round trip failed for {original}"

    def test_encode_rejects_oversized(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _encode_remaining_length

        with pytest.raises(ValueError):
            _encode_remaining_length(268_435_456)

    def test_decode_rejects_truncated(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _decode_remaining_length

        with pytest.raises(ValueError):
            _decode_remaining_length(b"\xff\x80", start=1)  # continuation but no more bytes


# ---------- Frame builders ----------


class TestFrameBuilders:
    def test_connect_starts_with_type_0x10(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _build_connect

        frame = _build_connect()
        assert frame[0] == 0x10

    def test_connect_has_mqtt_protocol_name(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _build_connect

        frame = _build_connect()
        assert b"MQTT" in frame

    def test_connect_uses_protocol_level_4(self) -> None:
        """MQTT 3.1.1 is protocol level 0x04."""
        from kryon.tools.ot.mqtt_industrial_audit import _build_connect

        frame = _build_connect()
        # Layout after fixed header: protoname_len(2) + 'MQTT' + level
        # Find 'MQTT' position then read +1.
        idx = frame.index(b"MQTT")
        assert frame[idx + 4] == 0x04

    def test_subscribe_starts_with_type_0x82(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _build_subscribe

        frame = _build_subscribe(1, "$SYS/#")
        assert frame[0] == 0x82

    def test_disconnect_is_two_bytes(self) -> None:
        from kryon.tools.ot.mqtt_industrial_audit import _build_disconnect

        assert _build_disconnect() == bytes([0xE0, 0x00])


# ---------- Result contract ----------


class TestResultContract:
    def test_result_is_frozen(self, patch_socket) -> None:
        from dataclasses import FrozenInstanceError

        from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit

        patch_socket([_connack(0), b""], drain_after=2)
        r = mqtt_industrial_audit("10.0.0.5")
        with pytest.raises(FrozenInstanceError):
            r.reachable = False  # type: ignore[misc]
