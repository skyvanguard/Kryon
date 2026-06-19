"""Batch I — Heartbleed (CVE-2014-0160) probe.

The ClientHello/heartbeat byte layout is validated, the TLS-record reader is
unit-tested, and the detection logic is exercised end-to-end against a fake
socket (vulnerable → CRITICAL finding; patched alert → no finding).
"""

from __future__ import annotations

import kryon.cli.tls_probes as tp
from kryon.cli.engage import DiscoveredService
from kryon.cli.tls_probes import _HEARTBEAT, _HELLO, run_tls_probes


def _svc(port: int = 443) -> DiscoveredService:
    return DiscoveredService(host="127.0.0.1", port=port, state="open", service="https")


class _FakeSock:
    """Minimal socket: serves a queued byte stream to recv(), no-ops the rest."""

    def __init__(self, stream: bytes):
        self._buf = stream

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, _t):
        pass

    def sendall(self, _data):
        pass

    def recv(self, n):
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk


def _record(ctype: int, payload: bytes) -> bytes:
    return bytes([ctype]) + b"\x03\x02" + len(payload).to_bytes(2, "big") + payload


def test_hello_and_heartbeat_well_formed():
    assert len(_HELLO) == 225 and _HELLO[:3] == b"\x16\x03\x02"  # TLS record header
    assert _HELLO[-3:] == b"\x00\x01\x01"  # heartbeat extension tail
    assert _HEARTBEAT == bytes.fromhex("1803020003014000")


def test_recv_tls_record_parses_header():
    rec = _record(24, b"ABCD")
    got = tp._recv_tls_record(_FakeSock(rec))
    assert got == (24, b"ABCD")


def test_heartbleed_vulnerable_detected(monkeypatch):
    server_hello_done = _record(22, b"\x0e\x00\x00\x00")  # handshake type 14
    leak = _record(24, b"A" * 100)  # heartbeat response far longer than our 1-byte payload
    monkeypatch.setattr(tp.socket, "create_connection", lambda *a, **k: _FakeSock(server_hello_done + leak))
    f = tp._check_heartbleed(_svc())
    assert f is not None and f.rule_id == "tls-heartbleed" and f.severity == "CRITICAL"


def test_heartbleed_patched_returns_none(monkeypatch):
    server_hello_done = _record(22, b"\x0e\x00\x00\x00")
    alert = _record(21, b"\x02\x33")  # fatal alert = server rejected the malformed heartbeat
    monkeypatch.setattr(tp.socket, "create_connection", lambda *a, **k: _FakeSock(server_hello_done + alert))
    assert tp._check_heartbleed(_svc()) is None


def test_run_tls_probes_graceful_on_dead_port():
    assert isinstance(run_tls_probes(_svc(1)), list)  # connection refused → []
