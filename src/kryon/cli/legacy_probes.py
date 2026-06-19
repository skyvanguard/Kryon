"""Batch H — deterministic detectors for legacy / IoT / OT services that should
not be exposed: unauthenticated X11, IPMI (hash-dump surface), open TFTP, CUPS,
BACnet (OT), and finger (user-info leak). Each is CONFIRMED by a protocol response
(not just an open port). READ-ONLY, graceful.

Imports utilities from service_probes (one-way; engage imports the probe modules
lazily, so no import cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _http_get, _tcp, _udp


def _check_x11(svc: DiscoveredService) -> Finding | None:
    """Open X11 server: X11 connection-setup with empty auth → reply byte 0x01
    (Success) means the server accepts unauthenticated clients (keylogging/screen)."""
    # byte-order 'l', pad, protocol-major 11, minor 0, auth-name-len 0, auth-data-len 0, pad
    setup = b"\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    resp = _tcp(svc.host, svc.port, setup, 32)
    if resp and len(resp) >= 1 and resp[0] == 0x01:
        return _f(
            svc, "CWE-306", "HIGH", "x11-open",
            f"Servidor X11 SIN autenticación en {svc.host}:{svc.port} — captura de pantalla/teclado remota.",
            "X11 connection-setup con auth vacía → respuesta 0x01 (Success, sin MIT-MAGIC-COOKIE)",
            "Deshabilitar TCP en X (`-nolisten tcp`); usar xauth/ssh X-forwarding; no exponer 6000-6005.",
        )
    return None


def _check_ipmi(svc: DiscoveredService) -> Finding | None:
    """IPMI reachable (623/udp). IPMI is notoriously weak (cipher-0 auth bypass +
    RAKP hash disclosure CVE-2013-4786). A valid Get-Channel-Auth-Cap response confirms it."""
    # RMCP + IPMI v1.5 Get Channel Authentication Capabilities (channel 0x0e, priv ADMIN)
    probe = bytes.fromhex("0600ff07000000000000000000092018c8810038 0e0431".replace(" ", ""))
    resp = _udp(svc.host, svc.port, probe, 256)
    if resp and len(resp) >= 8 and resp[0] == 0x06 and resp[3] == 0x07:
        return _f(
            svc, "CWE-306", "HIGH", "ipmi-exposed",
            f"IPMI/BMC expuesto en {svc.host}:{svc.port}/udp — superficie cipher-0 + dump de hashes RAKP (CVE-2013-4786).",
            "RMCP Get Channel Auth Capabilities → respuesta IPMI válida",
            "Segmentar la red de management (BMC) en VLAN aislada/sin ruteo; deshabilitar cipher-0; firmware al día.",
        )
    return None


def _check_tftp(svc: DiscoveredService) -> Finding | None:
    """Open TFTP (69/udp): RRQ for a non-existent file → ERROR (opcode 5) or DATA
    (opcode 3) confirms an anonymous file-transfer service (config exfil surface)."""
    rrq = b"\x00\x01" + b"kryon_probe_nonexistent\x00netascii\x00"
    resp = _udp(svc.host, svc.port, rrq, 128)
    if resp and len(resp) >= 2 and resp[0] == 0x00 and resp[1] in (0x03, 0x05):
        return _f(
            svc, "CWE-306", "MEDIUM", "tftp-open",
            f"Servicio TFTP abierto en {svc.host}:{svc.port}/udp — transferencia de archivos sin autenticación.",
            "RRQ de archivo inexistente → respuesta TFTP (DATA/ERROR) = servicio activo",
            "Deshabilitar TFTP si no es necesario; restringir a la VLAN de aprovisionamiento; nunca a internet.",
        )
    return None


def _check_cups(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """CUPS web admin exposed (631). Recent unauth-RCE chain CVE-2024-47176/47076/47175/47177."""
    r = _http_get(svc.host, svc.port, "/", scheme=scheme)
    if r and r[0] in (200, 401, 403) and ("CUPS" in r[1] or "cups" in r[1].lower() or "Common UNIX Printing" in r[1]):
        return _f(
            svc, "CWE-306", "MEDIUM", "cups-exposed",
            f"CUPS (servidor de impresión) expuesto en {svc.host}:{svc.port} — superficie CVE-2024-47176 (RCE vía IPP).",
            "GET / → página de administración CUPS",
            "Restringir CUPS a localhost (Listen localhost:631); deshabilitar cups-browsed; parchear.",
        )
    return None


def _check_bacnet(svc: DiscoveredService) -> Finding | None:
    """BACnet/IP (47808/udp) OT device. Who-Is → I-Am response confirms an exposed
    building-automation controller (HVAC/access-control)."""
    # BVLC (Original-Unicast-NPDU) + NPDU + APDU Who-Is (unconfirmed service 8)
    whois = bytes.fromhex("810b000c0120ffff00ff1008")
    resp = _udp(svc.host, svc.port, whois, 128)
    if resp and len(resp) >= 6 and resp[0] == 0x81:  # BVLC reply (I-Am)
        return _f(
            svc, "CWE-306", "MEDIUM", "bacnet-exposed",
            f"Dispositivo BACnet/IP expuesto en {svc.host}:{svc.port}/udp — automatización de edificios (OT) sin auth.",
            "Who-Is → I-Am (BVLC) = controlador BACnet alcanzable",
            "Aislar la red OT/BMS (sin ruteo a IT/internet); BACnet/SC con TLS donde sea posible.",
        )
    return None


def _check_finger(svc: DiscoveredService) -> Finding | None:
    """finger (79) leaks local user info (login, home, shell, last login)."""
    resp = _tcp(svc.host, svc.port, b"root\r\n", 512)
    if resp:
        text = resp.decode("latin-1", "replace")
        if any(k in text for k in ("Login:", "Directory:", "Last login", "Name:", "Shell:")):
            return _f(
                svc, "CWE-200", "LOW", "finger-exposed",
                f"Servicio finger en {svc.host}:{svc.port} filtra información de usuarios locales.",
                "Query 'root' → respuesta con Login/Directory/Shell",
                "Deshabilitar fingerd (servicio legacy sin utilidad operativa).",
            )
    return None


# Port → legacy/IoT detectors.
_LEGACY_PROBES = (
    (lambda s: 6000 <= s.port <= 6005, _check_x11),
    (lambda s: s.port == 623, _check_ipmi),
    (lambda s: s.port == 69, _check_tftp),
    (lambda s: s.port == 631, _check_cups),
    (lambda s: s.port == 47808, _check_bacnet),
    (lambda s: s.port == 79, _check_finger),
)


def run_legacy_probes(svc: DiscoveredService) -> list[Finding]:
    """Run matching legacy/IoT probes against a discovered service. Never raises."""
    out: list[Finding] = []
    for matches, probe in _LEGACY_PROBES:
        try:
            if matches(svc):
                f = probe(svc)
                if f:
                    out.append(f)
        except Exception:  # noqa: BLE001 — a probe must never break the sweep
            continue
    return out
