"""Shared low-level primitives for the deterministic probe layer: the Finding
helper, raw TCP/UDP socket probes, the HTTP shim, plus the common timeout and
TLS-port constants. These lived in ``service_probes`` (the largest module, ~800
lines) and were imported by ~13 sibling modules — pulling them here breaks that
coupling and gives every probe module one obvious place to import from.

``service_probes`` re-exports these names, so existing
``from kryon.cli.service_probes import _f, _tcp, ...`` imports (and the tests that
monkeypatch them) keep working unchanged.

Imports the data types from engage at module scope; engage imports the probe
modules lazily, so there is no import cycle (engage is fully loaded by the time
this is first imported via a probe module).
"""

from __future__ import annotations

import socket

from kryon.cli.engage import DiscoveredService, Finding, make_finding

DEFAULT_T = 4.0  # default probe timeout (s); modules needing longer override per-call
# TLS-bearing service ports (https/imaps/pop3s/smtps/ldaps/ftps/sip-tls/…).
TLS_PORTS = (443, 8443, 993, 995, 465, 636, 990, 5061, 9443)
TLS_SERVICES = ("https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps")


def _f(svc: DiscoveredService, cwe: str, sev: str, rule_id: str, msg: str, evidence: str, fix: str) -> Finding:
    """Build a Finding for a host:port service (the probe-layer convenience wrapper)."""
    return make_finding(cwe, sev, f"{svc.host}:{svc.port}", rule_id, msg, evidence=evidence, remediation=fix)


def _tcp(host: str, port: int, send: bytes = b"", recv: int = 512, timeout: float = DEFAULT_T) -> bytes | None:
    """Open TCP, optionally send, read up to ``recv`` bytes. None on any failure."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if send:
                s.sendall(send)
            return s.recv(recv)
    except (TimeoutError, OSError):
        return None


def _udp(host: str, port: int, payload: bytes, recv: int = 512, timeout: float = DEFAULT_T) -> bytes | None:
    """Send one UDP datagram and read the reply. None on any failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(payload, (host, port))
            data, _ = s.recvfrom(recv)
            return data
        finally:
            s.close()
    except (TimeoutError, OSError):
        return None


def _http_get(host: str, port: int, path: str, scheme: str = "http", auth: str = "",
              timeout: float = DEFAULT_T) -> tuple[int, str] | None:
    """GET a path; return (status, body[:4000]) or None on connection error. 401/403
    surface as their status so callers can tell "auth enforced" from "open"."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(host, port, path, scheme=scheme, auth=auth, timeout=timeout)
    return (r.status, r.body) if r else None
