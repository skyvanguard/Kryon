"""F84.4 — tests for kryon.tools.ot.iec104_probe."""

from __future__ import annotations

import socket
import struct
from typing import Iterator

import pytest


# ---------- Frame helpers ----------


def _u_frame(control_byte: int) -> bytes:
    """Standard U-format APCI: 0x68 0x04 ctrl 0x00 0x00 0x00."""
    return struct.pack(">BBBBBB", 0x68, 0x04, control_byte, 0x00, 0x00, 0x00)


_STARTDT_CON = _u_frame(0x0B)
_STOPDT_CON = _u_frame(0x23)
_TESTFR_CON = _u_frame(0x83)


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
        from kryon.tools.ot.iec104_probe import iec104_probe

        class _Refused:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def settimeout(self, _t): pass
            def connect(self, _a): raise OSError("refused")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **k: _Refused())
        r = iec104_probe("10.255.255.255")
        assert r.reachable is False
        assert "tcp_connect_failed" in r.error
        assert r.has_unauth_exposure is False


# ---------- STARTDT handshake ----------


class TestStartDt:
    def test_startdt_confirmed_marks_unauth_exposure(self, patch_socket) -> None:
        from kryon.tools.ot.iec104_probe import iec104_probe

        # 3 sendalls: STARTDT_ACT, TESTFR_ACT, STOPDT_ACT (cleanup, no recv).
        replies = [_STARTDT_CON, _TESTFR_CON, b""]
        patch_socket(replies)

        r = iec104_probe("10.0.0.5")
        assert r.reachable is True
        assert r.responds_to_iec104 is True
        assert r.startdt_confirmed is True
        assert r.testfr_confirmed is True
        assert r.has_unauth_exposure is True

    def test_startdt_rejected_marks_protected(self, patch_socket) -> None:
        from kryon.tools.ot.iec104_probe import iec104_probe

        # Server replied STOPDT_CON (rejecting the activation).
        replies = [_STOPDT_CON]
        patch_socket(replies)

        r = iec104_probe("10.0.0.5")
        assert r.reachable is True
        assert r.responds_to_iec104 is True
        assert r.startdt_confirmed is False
        assert r.has_unauth_exposure is False

    def test_no_response_yields_no_iec104(self, patch_socket) -> None:
        from kryon.tools.ot.iec104_probe import iec104_probe

        replies = [b""]
        patch_socket(replies)

        r = iec104_probe("10.0.0.5")
        assert r.reachable is True
        assert r.responds_to_iec104 is False
        assert r.startdt_confirmed is False

    def test_garbage_response_not_iec104(self, patch_socket) -> None:
        from kryon.tools.ot.iec104_probe import iec104_probe

        # Random non-0x68 bytes — definitely not IEC 104.
        replies = [b"\x00" * 32]
        patch_socket(replies)

        r = iec104_probe("10.0.0.5")
        assert r.responds_to_iec104 is False
        assert r.startdt_confirmed is False


# ---------- TESTFR liveness ----------


class TestTestFr:
    def test_testfr_disabled_skips_liveness_check(self, patch_socket) -> None:
        from kryon.tools.ot.iec104_probe import iec104_probe

        replies = [_STARTDT_CON, b""]  # STARTDT then immediate STOPDT cleanup
        patch_socket(replies)

        r = iec104_probe("10.0.0.5", test_link_alive=False)
        assert r.startdt_confirmed is True
        assert r.testfr_confirmed is False  # not attempted

    def test_testfr_failure_does_not_undo_startdt_finding(
        self, patch_socket,
    ) -> None:
        """STARTDT was confirmed; TESTFR may fail (network glitch, slow
        firewall) — that doesn't cancel the unauth-exposure finding."""
        from kryon.tools.ot.iec104_probe import iec104_probe

        replies = [_STARTDT_CON, b"\x00\x00\x00", b""]
        patch_socket(replies)

        r = iec104_probe("10.0.0.5")
        assert r.startdt_confirmed is True
        assert r.testfr_confirmed is False
        assert r.has_unauth_exposure is True


# ---------- Frame builders ----------


class TestFrameBuilders:
    def test_u_frame_starts_with_iec_magic(self) -> None:
        from kryon.tools.ot.iec104_probe import _build_u_frame

        frame = _build_u_frame(0x07)
        assert frame[0] == 0x68

    def test_u_frame_apdu_length_is_4(self) -> None:
        from kryon.tools.ot.iec104_probe import _build_u_frame

        frame = _build_u_frame(0x07)
        assert frame[1] == 0x04

    def test_u_frame_carries_control_byte(self) -> None:
        from kryon.tools.ot.iec104_probe import _build_u_frame

        frame_start = _build_u_frame(0x07)
        frame_test = _build_u_frame(0x43)
        assert frame_start[2] == 0x07
        assert frame_test[2] == 0x43

    def test_u_frame_total_length_is_6(self) -> None:
        """APCI = 6 bytes total (start + length-byte + 4 control bytes)."""
        from kryon.tools.ot.iec104_probe import _build_u_frame

        assert len(_build_u_frame(0x07)) == 6


# ---------- Frame validators ----------


class TestFrameValidators:
    def test_valid_iec_frame_recognised(self) -> None:
        from kryon.tools.ot.iec104_probe import _is_iec104_frame

        assert _is_iec104_frame(_STARTDT_CON) is True

    def test_short_response_rejected(self) -> None:
        from kryon.tools.ot.iec104_probe import _is_iec104_frame

        assert _is_iec104_frame(b"\x68") is False
        assert _is_iec104_frame(b"") is False

    def test_wrong_magic_rejected(self) -> None:
        from kryon.tools.ot.iec104_probe import _is_iec104_frame

        assert _is_iec104_frame(b"\x00\x04\x07\x00\x00\x00") is False

    def test_extreme_apdu_length_rejected(self) -> None:
        from kryon.tools.ot.iec104_probe import _is_iec104_frame

        # length 0xFF = 255 > spec max 253.
        assert _is_iec104_frame(b"\x68\xff" + b"\x00" * 16) is False
        # length 2 < min 4.
        assert _is_iec104_frame(b"\x68\x02") is False


# ---------- Result contract ----------


class TestResultContract:
    def test_result_is_frozen(self, patch_socket) -> None:
        from dataclasses import FrozenInstanceError

        from kryon.tools.ot.iec104_probe import iec104_probe

        patch_socket([_STARTDT_CON, _TESTFR_CON, b""])
        r = iec104_probe("10.0.0.5")
        with pytest.raises(FrozenInstanceError):
            r.reachable = False  # type: ignore[misc]
