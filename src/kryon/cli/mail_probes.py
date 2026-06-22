"""Batch R — IMAP/POP3 cleartext-auth posture. A mail server that does not offer
STARTTLS/STLS (and doesn't disable plaintext login) lets credentials cross the
wire in the clear. Complements the SMTP cleartext-AUTH check already in
service_probes. READ-ONLY (CAPABILITY/CAPA only), graceful.
"""

from __future__ import annotations

import socket

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import DEFAULT_T as _T
from kryon.cli.service_probes import _f


def _banner_and_caps(host: str, port: int, query: bytes, ok_prefix: bytes) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            if not s.recv(256).startswith(ok_prefix):
                return None
            s.sendall(query)
            return s.recv(1024).decode("latin-1", "replace")
    except (TimeoutError, OSError):
        return None


def _check_imap(svc: DiscoveredService) -> Finding | None:
    caps = _banner_and_caps(svc.host, svc.port, b"a CAPABILITY\r\n", b"* OK")
    if caps is None:
        return None
    up = caps.upper()
    if "STARTTLS" not in up and "LOGINDISABLED" not in up:
        return _f(svc, "CWE-319", "MEDIUM", "imap-cleartext-auth",
                  f"IMAP sin STARTTLS en {svc.host}:{svc.port} — login en texto plano (credenciales expuestas).",
                  "CAPABILITY no anuncia STARTTLS ni LOGINDISABLED",
                  "Habilitar STARTTLS o usar IMAPS (993); anunciar LOGINDISABLED hasta que haya TLS.")
    return None


def _check_pop3(svc: DiscoveredService) -> Finding | None:
    caps = _banner_and_caps(svc.host, svc.port, b"CAPA\r\n", b"+OK")
    if caps is None:
        return None
    if "STLS" not in caps.upper():
        return _f(svc, "CWE-319", "MEDIUM", "pop3-cleartext-auth",
                  f"POP3 sin STLS en {svc.host}:{svc.port} — USER/PASS en texto plano.",
                  "CAPA no anuncia STLS",
                  "Habilitar STLS o usar POP3S (995); rechazar USER/PASS sobre conexiones sin cifrar.")
    return None


def run_mail_probes(svc: DiscoveredService) -> list[Finding]:
    """IMAP(143)/POP3(110) cleartext-auth posture. Never raises."""
    out: list[Finding] = []
    try:
        if svc.service == "imap" or svc.port == 143:
            f = _check_imap(svc)
            if f:
                out.append(f)
        elif svc.service in ("pop3", "pop") or svc.port == 110:
            f = _check_pop3(svc)
            if f:
                out.append(f)
    except Exception:  # noqa: BLE001
        pass
    return out
