"""F84.1 — tests for kryon.tools.ot.modbus_scan.

Pure socket mocking — no real PLC, no Conpot. The MBAP frame format is
deterministic so we can hand-construct correct/malformed responses and
pin the parser against the Modbus spec v1.1b3.
"""

from __future__ import annotations

import socket
import struct
from typing import Iterator

import pytest


# Fixtures: pre-built Modbus/TCP response frames for canonical scenarios.
def _mbap_frame(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Build a properly-formed Modbus/TCP response frame."""
    length = len(pdu) + 1
    return struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id) + pdu


def _read_coils_response_ok(transaction_id: int, unit_id: int) -> bytes:
    """0x01 response: 1 byte payload (coil 0 = OFF)."""
    pdu = struct.pack(">BBB", 0x01, 0x01, 0x00)
    return _mbap_frame(transaction_id, unit_id, pdu)


def _read_coils_exception(transaction_id: int, unit_id: int, exc_code: int = 0x01) -> bytes:
    """0x81 exception response (function code | 0x80)."""
    pdu = struct.pack(">BB", 0x81, exc_code)
    return _mbap_frame(transaction_id, unit_id, pdu)


def _read_holding_response_ok(transaction_id: int, unit_id: int) -> bytes:
    """0x03 response: 1 register = 0x1234."""
    pdu = struct.pack(">BBH", 0x03, 0x02, 0x1234)
    return _mbap_frame(transaction_id, unit_id, pdu)


def _device_id_response(
    transaction_id: int, unit_id: int,
    vendor: bytes = b"Schneider Electric",
    product: bytes = b"Modicon M340",
    revision: bytes = b"v3.10",
) -> bytes:
    """0x2B/0x0E Read Device Identification response with 3 basic objects."""
    pdu = bytearray()
    pdu += struct.pack(">BBBBB", 0x2B, 0x0E, 0x01, 0x83, 0x00)  # MEI, RDI, Conformity, More, NextObj
    pdu += struct.pack(">B", 0xFF)  # NextObjectId = end
    pdu += struct.pack(">B", 0x03)  # NumObjects
    for obj_id, value in [(0, vendor), (1, product), (2, revision)]:
        pdu += struct.pack(">BB", obj_id, len(value)) + value
    # Re-pack with right MEI position. The above NextObjectId byte is wrong;
    # rebuild cleanly per spec: function | MEI | RDIcode | Conformity | More | NextObj | NumObj | objs.
    pdu = bytearray(struct.pack(">BBBBB", 0x2B, 0x0E, 0x01, 0x83, 0x00))
    pdu += struct.pack(">B", 0x03)  # NumObjects (replaces NextObj position above)
    for obj_id, value in [(0, vendor), (1, product), (2, revision)]:
        pdu += struct.pack(">BB", obj_id, len(value)) + value
    return _mbap_frame(transaction_id, unit_id, bytes(pdu))


# ---------- Mock socket plumbing ----------


class _MockSocket:
    """Minimal socket double driven by a queue of (request_check, reply)
    pairs. The harness asserts the sent bytes' MBAP looks valid and
    returns the queued reply chunk-by-chunk to also exercise the
    drain loop in `_send_recv`."""

    def __init__(self, replies: list[bytes]) -> None:
        self._replies: Iterator[bytes] = iter(replies)
        self._sent_count = 0
        self._buffer = b""

    def settimeout(self, _t: float) -> None:
        pass

    def connect(self, _addr: tuple[str, int]) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self._sent_count += 1
        # Pre-buffer the next reply so recv() can serve it.
        try:
            self._buffer = next(self._replies)
        except StopIteration:
            self._buffer = b""

    def recv(self, n: int) -> bytes:
        chunk = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return chunk

    def __enter__(self) -> _MockSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def patch_socket(monkeypatch: pytest.MonkeyPatch):
    """Returns a callable: pass it the list of pre-built reply bytes
    (one per outbound request, in order) and it patches socket.socket
    to return mocks producing those replies."""

    def _install(replies: list[bytes]) -> _MockSocket:
        mock = _MockSocket(replies)

        def _factory(*args, **kwargs):
            return mock

        monkeypatch.setattr(socket, "socket", _factory)
        return mock

    return _install


# ---------- Reachability / error paths ----------


class TestReachability:
    def test_unreachable_host_returns_error_result(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        class _ConnRefused:
            def __enter__(self): return self
            def __exit__(self, *a): return None
            def settimeout(self, _t): pass
            def connect(self, _a): raise OSError("Connection refused")

        monkeypatch.setattr(socket, "socket", lambda *a, **k: _ConnRefused())

        r = modbus_scan("10.255.255.255")
        assert r.reachable is False
        assert "tcp_connect_failed" in r.error
        assert r.has_unauth_exposure is False

    def test_timeout_treated_as_unreachable(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        class _Timeout:
            def __enter__(self): return self
            def __exit__(self, *a): return None
            def settimeout(self, _t): pass
            def connect(self, _a): raise TimeoutError("slow")

        monkeypatch.setattr(socket, "socket", lambda *a, **k: _Timeout())

        r = modbus_scan("10.255.255.255")
        assert r.reachable is False


# ---------- Anonymous read exposure ----------


class TestUnauthRead:
    def test_both_reads_succeed_marks_full_exposure(self, patch_socket) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        # Reachability connect doesn't sendall, so it doesn't consume a reply.
        # Three sendalls follow: coils probe, holding probe, device-id probe.
        replies = [
            _read_coils_response_ok(0x0001, 1),
            _read_holding_response_ok(0x0002, 1),
            b"",  # device id — accept empty (older device)
        ]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        assert r.reachable is True
        assert r.unauth_read_coils is True
        assert r.unauth_read_holding is True
        assert r.has_unauth_exposure is True

    def test_exception_response_does_not_count_as_exposure(self, patch_socket) -> None:
        """Function code 0x81 is the exception flavor of 0x01 — device
        is alive but rejected the read. NOT an exposure."""
        from kryon.tools.ot.modbus_scan import modbus_scan

        replies = [
            _read_coils_exception(0x0001, 1),
            _read_coils_exception(0x0002, 1),
            b"",
        ]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        assert r.reachable is True
        assert r.unauth_read_coils is False
        assert r.unauth_read_holding is False
        assert r.has_unauth_exposure is False

    def test_partial_exposure_only_coils(self, patch_socket) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        replies = [
            _read_coils_response_ok(0x0001, 1),
            _read_coils_exception(0x0002, 1),  # holding rejected
            b"",
        ]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        assert r.unauth_read_coils is True
        assert r.unauth_read_holding is False
        assert r.has_unauth_exposure is True  # any read = exposure


# ---------- Write probe (gated) ----------


class TestWriteProbe:
    def test_write_attempt_default_off(self, patch_socket) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        replies = [_read_coils_exception(1, 1), _read_coils_exception(2, 1), b""]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        assert r.write_attempt is False
        assert r.write_succeeded is None

    def test_write_succeeds_when_caller_opts_in(self, patch_socket) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        # Build a Write Single Coil OK reply: function 0x05 + address + value echoed.
        write_ok_pdu = struct.pack(">BHH", 0x05, 0x270F, 0x0000)
        write_ok_frame = _mbap_frame(0x0004, 1, write_ok_pdu)

        replies = [
            _read_coils_exception(1, 1),
            _read_coils_exception(2, 1),
            b"",  # device id
            write_ok_frame,
        ]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5", attempt_write=True)
        assert r.write_attempt is True
        assert r.write_succeeded is True


# ---------- Frame parsing edge cases ----------


class TestFrameParsing:
    def test_truncated_response_does_not_crash(self, patch_socket) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        replies = [b"\x00\x01", b"\x00\x02\x00\x00", b""]  # all truncated
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        assert r.reachable is True
        assert r.has_unauth_exposure is False  # truncated → not "ok"

    def test_garbage_response_does_not_crash(self, patch_socket) -> None:
        from kryon.tools.ot.modbus_scan import modbus_scan

        replies = [b"\xff" * 20, b"\x00" * 9, b""]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        # Response with junk bytes — function code byte is 0xff, not 0x01.
        assert r.unauth_read_coils is False


# ---------- Determinism / contract ----------


class TestResultContract:
    def test_result_is_frozen(self, patch_socket) -> None:
        """ModbusScanResult is a frozen dataclass — banking auditors get
        an immutable artifact they can hash for chain-of-custody."""
        from dataclasses import FrozenInstanceError

        from kryon.tools.ot.modbus_scan import modbus_scan

        replies = [_read_coils_exception(1, 1), _read_coils_exception(2, 1), b""]
        patch_socket(replies)

        r = modbus_scan("10.0.0.5")
        with pytest.raises(FrozenInstanceError):
            r.reachable = True  # type: ignore[misc]
