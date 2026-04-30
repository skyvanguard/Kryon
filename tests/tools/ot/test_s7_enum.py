"""F84.3 — tests for kryon.tools.ot.s7_enum.

Mock-socket pattern reused from F84.1/F84.2. Frame layouts per
Wireshark s7comm.c dissector.
"""

from __future__ import annotations

import socket
import struct
from typing import Iterator

import pytest


# ---------- Frame helpers ----------


def _tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 0x03, 0x00, 4 + len(payload)) + payload


def _cotp_connection_confirm() -> bytes:
    """Minimal CC PDU: length(1) | 0xD0 (CC) | DST_REF(2) | SRC_REF(2)
    | Class+Option(1) | optional params..."""
    cotp = struct.pack(">BBHHB", 0x06, 0xD0, 0x0001, 0x0002, 0x00)
    return _tpkt(cotp)


def _cotp_connection_reject() -> bytes:
    """Disconnect Request (DR) PDU code 0x80 — server says no."""
    cotp = struct.pack(">BBHHB", 0x06, 0x80, 0x0000, 0x0001, 0x00)
    return _tpkt(cotp)


def _s7_setup_ack() -> bytes:
    """COTP Data PDU + S7 ROSCTR=3 (Ack-Data). Minimal length to pass
    the 9-byte check."""
    s7_pdu = struct.pack(
        ">BBHHHHBB",
        0x32, 0x03, 0x0000, 0x0000, 0x0008, 0x0000, 0x00, 0x00,
    )
    cotp = struct.pack(">BBB", 0x02, 0xF0, 0x80) + s7_pdu
    return _tpkt(cotp)


def _s7_setup_no_reply() -> bytes:
    """Server sent a frame but ROSCTR isn't 2 or 3 (could be Job=1 or
    Userdata=7 — neither is a Setup ack)."""
    s7_pdu = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, 0x0000, 0x0000, 0x0000)
    cotp = struct.pack(">BBB", 0x02, 0xF0, 0x80) + s7_pdu
    return _tpkt(cotp)


def _szl_response(*ascii_strings: bytes) -> bytes:
    """Synthetic SZL response — pad header bytes then drop ASCII payload
    that the heuristic parser can extract. Production parser (F84.3
    Sprint 2) would fully parse SZL records."""
    s7_pdu = struct.pack(
        ">BBHHHH",
        0x32, 0x07, 0x0000, 0x0001, 0x000C, 0x0040,
    )
    s7_pdu += b"\x00" * 20  # pad — parser scans from offset 20
    for s in ascii_strings:
        s7_pdu += s + b"\x00"  # null-terminate so each string is its own run
    cotp = struct.pack(">BBB", 0x02, 0xF0, 0x80) + s7_pdu
    return _tpkt(cotp)


# ---------- Mock socket ----------


class _MockSocket:
    def __init__(self, replies: list[bytes]) -> None:
        self._replies: Iterator[bytes] = iter(replies)
        self._buffer = b""
        self.closed = False

    def settimeout(self, _t: float) -> None: pass
    def connect(self, _addr: tuple[str, int]) -> None: pass

    def sendall(self, _data: bytes) -> None:
        try:
            self._buffer = next(self._replies)
        except StopIteration:
            self._buffer = b""

    def recv(self, n: int) -> bytes:
        chunk = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return chunk

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> "_MockSocket": return self
    def __exit__(self, *exc: object) -> None: self.close()


@pytest.fixture
def patch_socket(monkeypatch: pytest.MonkeyPatch):
    def _install(replies: list[bytes]) -> _MockSocket:
        mock = _MockSocket(replies)
        monkeypatch.setattr(socket, "socket", lambda *a, **k: mock)
        return mock
    return _install


# ---------- Reachability ----------


class TestReachability:
    def test_unreachable_host_returns_error(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.tools.ot.s7_enum import s7_enum

        class _Refused:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def settimeout(self, _t): pass
            def connect(self, _a): raise OSError("refused")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **k: _Refused())
        r = s7_enum("10.255.255.255")
        assert r.reachable is False
        assert "tcp_connect_failed" in r.error
        assert r.has_unauth_exposure is False


# ---------- COTP handshake ----------


class TestCotpHandshake:
    def test_cotp_reject_marks_no_session(self, patch_socket) -> None:
        from kryon.tools.ot.s7_enum import s7_enum

        replies = [_cotp_connection_reject(), _s7_setup_ack(), b""]
        patch_socket(replies)

        r = s7_enum("10.0.0.5")
        assert r.reachable is True
        assert r.cotp_connected is False
        assert r.s7_session_established is False
        assert r.error == "cotp_connection_refused"
        assert r.has_unauth_exposure is False

    def test_cotp_accepts_then_s7_rejected(self, patch_socket) -> None:
        from kryon.tools.ot.s7_enum import s7_enum

        replies = [_cotp_connection_confirm(), _s7_setup_no_reply()]
        patch_socket(replies)

        r = s7_enum("10.0.0.5")
        assert r.cotp_connected is True
        assert r.s7_session_established is False
        assert r.error == "s7_setup_rejected"

    def test_cotp_garbage_response_marks_failure(self, patch_socket) -> None:
        from kryon.tools.ot.s7_enum import s7_enum

        replies = [b"HTTP/1.1 200 OK\r\n", b""]
        patch_socket(replies)

        r = s7_enum("10.0.0.5")
        assert r.cotp_connected is False


# ---------- S7 setup + SZL ----------


class TestS7Session:
    def test_full_handshake_marks_unauth_exposure(self, patch_socket) -> None:
        from kryon.tools.ot.s7_enum import s7_enum

        replies = [
            _cotp_connection_confirm(),
            _s7_setup_ack(),
            _szl_response(b"6ES7 315-2EH14-0AB0", b"V 3.2.6", b"PLC_BCP_HVAC"),
        ]
        patch_socket(replies)

        r = s7_enum("10.0.0.5")
        assert r.cotp_connected is True
        assert r.s7_session_established is True
        assert r.has_unauth_exposure is True
        assert r.module_identification.get("order_code") == "6ES7 315-2EH14-0AB0"
        assert "V 3.2.6" in r.plc_firmware_version

    def test_szl_failure_does_not_mask_session_finding(self, patch_socket) -> None:
        """SZL read may fail (older firmware, custom config) — session
        establishment is the actual finding, SZL is informational."""
        from kryon.tools.ot.s7_enum import s7_enum

        replies = [_cotp_connection_confirm(), _s7_setup_ack(), b""]
        patch_socket(replies)

        r = s7_enum("10.0.0.5")
        assert r.s7_session_established is True
        assert r.has_unauth_exposure is True
        assert r.module_identification == {}

    def test_szl_no_order_code_yields_empty_dict_keys(self, patch_socket) -> None:
        """ASCII run that doesn't match the 6ES7 / firmware patterns is
        captured as generic szl_field_N entries — not pretended to be
        an order code."""
        from kryon.tools.ot.s7_enum import s7_enum

        replies = [
            _cotp_connection_confirm(),
            _s7_setup_ack(),
            _szl_response(b"genericstring"),
        ]
        patch_socket(replies)

        r = s7_enum("10.0.0.5")
        assert "order_code" not in r.module_identification
        # But the raw run was captured for the auditor to review.
        assert any(
            v == "genericstring" for v in r.module_identification.values()
        )


# ---------- Frame builders ----------


class TestFrameBuilders:
    def test_connection_request_starts_with_tpkt(self) -> None:
        from kryon.tools.ot.s7_enum import _build_cotp_connection_request

        frame = _build_cotp_connection_request()
        # TPKT version 3, reserved 0.
        assert frame[0] == 0x03
        assert frame[1] == 0x00

    def test_connection_request_has_cr_pdu_code(self) -> None:
        """COTP CR PDU code = 0xE0, at offset TPKT(4) + len(1) = 5."""
        from kryon.tools.ot.s7_enum import _build_cotp_connection_request

        frame = _build_cotp_connection_request()
        assert frame[5] == 0xE0

    def test_setup_communication_uses_s7_proto_id(self) -> None:
        """Protocol ID 0x32 marks an S7 PDU — at offset TPKT(4) + COTP(3) = 7."""
        from kryon.tools.ot.s7_enum import _build_s7_setup_communication

        frame = _build_s7_setup_communication()
        assert frame[7] == 0x32

    def test_dst_tsap_propagates_into_frame(self) -> None:
        """Verify the TSAP we requested is what gets serialized."""
        from kryon.tools.ot.s7_enum import _build_cotp_connection_request

        frame = _build_cotp_connection_request(dst_tsap=0x0103)
        # Find the 0xC2 (called TSAP) param header: length(1) PDU(1) DST_REF(2) SRC_REF(2) Opt(1)
        # = at offset 6+5=11; then 0xC1 src TSAP block (4 bytes), then 0xC2 block.
        # Just scan for 0xC2 0x02 followed by big-endian dst_tsap.
        tsap_bytes = struct.pack(">H", 0x0103)
        assert b"\xc2\x02" + tsap_bytes in frame


# ---------- Result contract ----------


class TestResultContract:
    def test_result_is_frozen(self, patch_socket) -> None:
        from dataclasses import FrozenInstanceError

        from kryon.tools.ot.s7_enum import s7_enum

        patch_socket([_cotp_connection_confirm(), _s7_setup_ack(), b""])
        r = s7_enum("10.0.0.5")
        with pytest.raises(FrozenInstanceError):
            r.reachable = False  # type: ignore[misc]
