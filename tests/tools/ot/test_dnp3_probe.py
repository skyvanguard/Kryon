"""F84.2 — tests for kryon.tools.ot.dnp3_probe.

Mock-socket pattern reused from F84.1 modbus tests. Frame layout per
IEEE 1815-2012; mocks construct legitimate DL headers + transport +
application bytes and verify the probe parses them correctly.
"""

from __future__ import annotations

import socket
import struct
from typing import Iterator

import pytest

# ---------- DNP3 frame helpers ----------


def _crc16_dnp(payload: bytes) -> int:
    """Use the production CRC routine — single source of truth."""
    from kryon.tools.ot.dnp3_probe import _dnp3_crc

    return _dnp3_crc(payload)


def _build_read_response(
    *,
    source: int = 4,
    destination: int = 1,
    iin1: int = 0x00,
    iin2: int = 0x00,
    function_code: int = 0x81,  # 0x81 = Read response, 0x83 = SAv5 challenge
) -> bytes:
    """Build a minimal valid DNP3 outstation response."""
    # User layer: transport(1) | app_ctrl(1) | func(1) | iin1(1) | iin2(1)
    user_data = struct.pack(">BBBBB", 0xC0, 0xC0, function_code, iin1, iin2)

    length = 5 + len(user_data)
    control = 0x44  # response from outstation
    dl_no_crc = struct.pack(
        "<BBBBHH", 0x05, 0x64, length, control, destination, source,
    )
    dl_crc = _crc16_dnp(dl_no_crc)
    dl = dl_no_crc + struct.pack("<H", dl_crc)

    user_with_crc = user_data + struct.pack("<H", _crc16_dnp(user_data))
    return dl + user_with_crc


# ---------- Mock socket plumbing ----------


class _MockSocket:
    def __init__(self, replies: list[bytes]) -> None:
        self._replies: Iterator[bytes] = iter(replies)
        self._buffer = b""

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

    def __enter__(self) -> _MockSocket: return self
    def __exit__(self, *exc: object) -> None: return None


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
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        class _Refused:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def settimeout(self, _t): pass
            def connect(self, _a): raise OSError("Connection refused")

        monkeypatch.setattr(socket, "socket", lambda *a, **k: _Refused())

        r = dnp3_probe("10.255.255.255")
        assert r.reachable is False
        assert "tcp_connect_failed" in r.error
        assert r.has_unauth_exposure is False


# ---------- Read response parsing ----------


class TestReadResponse:
    def test_unauth_read_succeeds_with_clean_iin(self, patch_socket) -> None:
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        replies = [_build_read_response(source=4, iin1=0x00, iin2=0x00)]
        patch_socket(replies)

        r = dnp3_probe("10.0.0.5")
        assert r.reachable is True
        assert r.responds_to_dnp3 is True
        assert r.outstation_address == 4
        assert r.secure_auth_v5_active is False
        assert r.has_unauth_exposure is True

    def test_iin_bits_parsed_correctly(self, patch_socket) -> None:
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        # iin1 0x80 = device_restart bit; iin2 0x20 = config_corrupt
        replies = [_build_read_response(iin1=0x80, iin2=0x20)]
        patch_socket(replies)

        r = dnp3_probe("10.0.0.5")
        assert r.iin_bits["device_restart"] is True
        assert r.iin_bits["config_corrupt"] is True
        assert r.iin_bits["broadcast"] is False  # negative case

    def test_sav5_challenge_marked_secure(self, patch_socket) -> None:
        """Function code 0x83 = SAv5 Authentication Challenge — device is
        DEMANDING credentials. NOT exposed."""
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        replies = [_build_read_response(function_code=0x83)]
        patch_socket(replies)

        r = dnp3_probe("10.0.0.5")
        assert r.responds_to_dnp3 is True
        assert r.secure_auth_v5_active is True
        assert r.has_unauth_exposure is False


# ---------- Garbage / non-DNP3 responses ----------


class TestNonDnp3Service:
    def test_response_without_start_bytes_is_not_dnp3(self, patch_socket) -> None:
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        replies = [b"HTTP/1.1 200 OK\r\n\r\n<html>"]
        patch_socket(replies)

        r = dnp3_probe("10.0.0.5")
        assert r.reachable is True
        assert r.responds_to_dnp3 is False
        assert r.has_unauth_exposure is False

    def test_truncated_response_treated_as_no_response(self, patch_socket) -> None:
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        replies = [b"\x05\x64\x05"]  # has start bytes, but truncated
        patch_socket(replies)

        r = dnp3_probe("10.0.0.5")
        assert r.responds_to_dnp3 is True  # has start bytes
        assert r.iin_bits == {}  # but IIN couldn't be parsed
        assert r.outstation_address is None

    def test_empty_response_is_not_dnp3(self, patch_socket) -> None:
        from kryon.tools.ot.dnp3_probe import dnp3_probe

        replies = [b""]
        patch_socket(replies)

        r = dnp3_probe("10.0.0.5")
        assert r.reachable is True
        assert r.responds_to_dnp3 is False


# ---------- CRC routine ----------


class TestCrc16Dnp:
    def test_crc_is_deterministic(self) -> None:
        from kryon.tools.ot.dnp3_probe import _dnp3_crc

        sample = b"\x05\x64\x14\xc4\x04\x00\x01\x00"
        c1 = _dnp3_crc(sample)
        c2 = _dnp3_crc(sample)
        assert c1 == c2

    def test_crc_changes_on_payload_change(self) -> None:
        from kryon.tools.ot.dnp3_probe import _dnp3_crc

        a = _dnp3_crc(b"\x00\x00\x00\x00")
        b = _dnp3_crc(b"\x00\x00\x00\x01")
        assert a != b

    def test_crc_returns_uint16(self) -> None:
        from kryon.tools.ot.dnp3_probe import _dnp3_crc

        result = _dnp3_crc(b"\xff" * 256)
        assert 0 <= result <= 0xFFFF


# ---------- Frame builder ----------


class TestFrameBuilder:
    def test_request_starts_with_dnp3_magic(self) -> None:
        from kryon.tools.ot.dnp3_probe import _build_read_class0_frame

        frame = _build_read_class0_frame()
        assert frame[:2] == b"\x05\x64"

    def test_request_has_destination_address(self) -> None:
        from kryon.tools.ot.dnp3_probe import _build_read_class0_frame

        frame = _build_read_class0_frame(destination=42, source=1)
        # Destination at offset 4-5 (LE).
        assert struct.unpack_from("<H", frame, 4)[0] == 42

    def test_request_has_correct_function_code(self) -> None:
        """App layer function code 0x01 = Read."""
        from kryon.tools.ot.dnp3_probe import _build_read_class0_frame

        frame = _build_read_class0_frame()
        # Layout: DL header (10) | transport (1) | app_ctrl (1) | func (1)
        assert frame[12] == 0x01


# ---------- Result contract ----------


class TestResultContract:
    def test_result_is_frozen(self, patch_socket) -> None:
        from dataclasses import FrozenInstanceError

        from kryon.tools.ot.dnp3_probe import dnp3_probe

        patch_socket([_build_read_response()])
        r = dnp3_probe("10.0.0.5")
        with pytest.raises(FrozenInstanceError):
            r.reachable = False  # type: ignore[misc]
