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
import ssl

from kryon.cli.engage import DiscoveredService, Finding, make_finding
from kryon.scoring.confidence import _VERIFICATION_BANDS, _VERIFICATION_THRESHOLD

DEFAULT_T = 4.0  # default probe timeout (s); modules needing longer override per-call
# TLS-bearing service ports (https/imaps/pop3s/smtps/ldaps/ftps/sip-tls/…).
TLS_PORTS = (443, 8443, 993, 995, 465, 636, 990, 5061, 9443)
TLS_SERVICES = ("https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps")


def _f(
    svc: DiscoveredService,
    cwe: str,
    sev: str,
    rule_id: str,
    msg: str,
    evidence: str,
    fix: str,
    *,
    verification_level: str = "confirmed",
) -> Finding:
    """Build a Finding for a host:port service (the probe-layer convenience wrapper).

    F210 — ``verification_level`` lets a probe declare a finding as inferred
    rather than directly probed (e.g. an exposed appliance whose CVE patch
    level was NOT confirmed). Default ``confirmed`` keeps confidence 1.0, so
    every existing caller is unchanged; ``heuristic``/``inferred`` derive a
    lower confidence + ``needs_verification`` from the band.
    """
    conf = _VERIFICATION_BANDS.get(verification_level, 1.0)
    return make_finding(
        cwe,
        sev,
        f"{svc.host}:{svc.port}",
        rule_id,
        msg,
        evidence=evidence,
        remediation=fix,
        confidence=conf,
        needs_verification=conf < _VERIFICATION_THRESHOLD,
        verification_level=verification_level,
    )


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


def _noverify_ctx() -> ssl.SSLContext:
    """A TLS-client context that does NOT validate the cert — probes inspect the
    cert/handshake themselves, they don't trust it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def peer_cert(host: str, port: int, timeout: float = DEFAULT_T) -> tuple[bytes | None, str] | None:
    """Raw TLS handshake → (DER cert bytes, negotiated cipher name), or None if the
    target isn't TLS / is unreachable. The single place the cert-inspection probes
    (cert expiry/SAN/hostname, weak cipher/key) get the peer certificate."""
    ctx = _noverify_ctx()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(
            s, server_hostname=host
        ) as ss:
            return ss.getpeercert(binary_form=True), (ss.cipher() or ("", "", 0))[0]
    except (OSError, ValueError):
        return None


def tls_handshake_ok(host: str, port: int, version, timeout: float = DEFAULT_T) -> bool:
    """True if the server completes a handshake when min/max TLS are pinned to
    ``version`` (with SECLEVEL=0 so modern OpenSSL will still offer legacy protocols).
    Used to detect that an obsolete TLS 1.0/1.1 is still accepted."""
    ctx = _noverify_ctx()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, OSError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host):
            return True
    except (OSError, ValueError):
        return False


def _unpack(entry):
    """Normalize a dispatch-table entry → (matcher, detector). Accepts a bare
    callable (no matcher → always run), a 2-tuple (matcher, detector), or a
    3-tuple (name, matcher, detector)."""
    if callable(entry):
        return None, entry
    if len(entry) == 2:
        return entry[0], entry[1]
    return entry[1], entry[2]  # (name, matcher, detector)


def run_table(svc, table, scheme: str | None = None) -> list[Finding]:
    """Run a probe dispatch table against a service — the one dispatch loop every
    ``run_*_probes`` shares. Each entry is a bare detector or a (matcher, detector)
    / (name, matcher, detector) tuple; a missing/None matcher always runs. Detectors
    are called ``detector(svc, scheme)`` when ``scheme`` is given, else ``detector(svc)``,
    and may return a Finding, a list of Findings, or None. One probe never breaks the rest."""
    import os
    from concurrent.futures import ThreadPoolExecutor

    if not table:
        return []

    def _run(entry) -> list:  # noqa: ANN001
        try:
            matcher, detector = _unpack(entry)
            if matcher is not None and not matcher(svc):
                return []
            res = detector(svc, scheme) if scheme is not None else detector(svc)
            if isinstance(res, list):
                return res
            return [res] if res else []
        except Exception:  # noqa: BLE001 — a probe must never break the sweep
            return []

    # Detectors are independent I/O calls — run concurrently by default (the
    # sequential loop dominated the deterministic phase). KRYON_PROBE_SERIAL=1
    # forces the old order for ultra-conservative / banca-safe runs.
    out: list[Finding] = []
    if os.environ.get("KRYON_PROBE_SERIAL", "").strip().lower() in ("1", "true", "yes", "on"):
        for entry in table:
            out.extend(_run(entry))
        return out

    with ThreadPoolExecutor(max_workers=min(16, len(table))) as ex:
        for res in ex.map(_run, table):
            out.extend(res)
    return out
