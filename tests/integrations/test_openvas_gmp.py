"""Raw GMP-over-socket transport — GmpConnection framing + gmp_socket_runner.
Sockets are faked; no network, no Greenbone, no gvm-cli."""

from __future__ import annotations

import pytest

from kryon.integrations.openvas.client import GmpConnection, OpenVASError, gmp_socket_runner


class _ChunkSocket:
    """recv() dribbles one response out in small chunks, then EOF."""

    def __init__(self, data: str, chunk: int = 5):
        self._d = data.encode("utf-8")
        self._p = 0
        self._c = chunk

    def recv(self, _n: int) -> bytes:
        if self._p >= len(self._d):
            return b""
        out = self._d[self._p : self._p + self._c]
        self._p += self._c
        return out


class _ReqRespSocket:
    """Models GMP request/response: each sendall arms the next response."""

    def __init__(self, responses, chunk: int = 5):
        self._responses = [r.encode("utf-8") for r in responses]
        self._idx = -1
        self._pos = 0
        self._chunk = chunk
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        self._idx += 1
        self._pos = 0

    def recv(self, _n: int) -> bytes:
        if not (0 <= self._idx < len(self._responses)):
            return b""
        cur = self._responses[self._idx]
        if self._pos >= len(cur):
            return b""
        out = cur[self._pos : self._pos + self._chunk]
        self._pos += self._chunk
        return out

    def close(self) -> None:
        self.closed = True


# --- GmpConnection framing ---


def test_read_response_reassembles_chunked_xml():
    conn = GmpConnection(_ChunkSocket("<foo><bar/></foo>"))
    assert conn.read_response() == "<foo><bar/></foo>"


def test_read_response_handles_self_closing_root():
    conn = GmpConnection(_ChunkSocket('<authenticate_response status="200"/>'))
    assert conn.read_response() == '<authenticate_response status="200"/>'


def test_read_response_premature_close_raises():
    conn = GmpConnection(_ChunkSocket("<foo><bar", chunk=100))  # never closes root
    with pytest.raises(OpenVASError, match="closed before"):
        conn.read_response()


# --- gmp_socket_runner ---


def test_runner_authenticates_then_returns_command_response():
    fake = _ReqRespSocket(
        [
            '<authenticate_response status="200"/>',
            '<get_results_response status="200"><result id="r"/></get_results_response>',
        ]
    )
    runner = gmp_socket_runner(username="admin", password="pw", connect=lambda: fake)
    out = runner("<get_results/>")
    assert "get_results_response" in out
    # sent: authenticate first, then the command.
    assert b"authenticate" in fake.sent[0]
    assert b"get_results" in fake.sent[1]
    assert fake.closed is True


def test_runner_auth_failure_raises():
    fake = _ReqRespSocket(['<authenticate_response status="400" status_text="Auth failed"/>'])
    runner = gmp_socket_runner(username="admin", password="bad", connect=lambda: fake)
    with pytest.raises(OpenVASError, match="authenticate"):
        runner("<get_results/>")
    assert fake.closed is True  # socket still closed on failure
