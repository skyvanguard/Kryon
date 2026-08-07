"""deterministic detectors for legacy / IoT / OT services that should
not be exposed: unauthenticated X11, IPMI (hash-dump surface), open TFTP, CUPS,
BACnet (OT), and finger (user-info leak). Each is CONFIRMED by a protocol response
(not just an open port). READ-ONLY, graceful.

Imports utilities from service_probes (one-way; engage imports the probe modules
lazily, so no import cycle).
"""

from __future__ import annotations

import socket

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import DEFAULT_T, _f, _http_get, _tcp, _udp, run_table


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


def _check_tr069(svc: DiscoveredService) -> Finding | None:
    """TR-069 CWMP (7547): the CPE WAN management plane on an embedded HTTP server
    (RomPager/GoAhead/gSOAP) — the Mirai/Eircom RCE vector when exposed to WAN."""
    resp = _tcp(svc.host, svc.port, b"GET / HTTP/1.0\r\nHost: kryon\r\n\r\n", 1024)
    if resp and (b"RomPager" in resp or b"GoAhead" in resp or b"gSOAP" in resp
                 or (b"WWW-Authenticate" in resp and b"Digest" in resp)):
        return _f(
            svc, "CWE-284", "HIGH", "tr069-cwmp-exposed",
            f"TR-069 CWMP expuesto en {svc.host}:{svc.port} — plano de gestión del CPE alcanzable (vector Mirai).",
            "GET / → servidor embebido (RomPager/GoAhead/gSOAP) o auth Digest del CWMP",
            "El CWMP solo debe hablar con el ACS del ISP; filtrar 7547 desde la WAN; parchear el firmware del CPE.",
        )
    return None


def _check_sip(svc: DiscoveredService) -> Finding | None:
    """SIP server (5060): OPTIONS → a SIP/2.0 status line confirms a PBX/proxy
    (enumeration + INVITE-amplification surface)."""
    req = (f"OPTIONS sip:probe@{svc.host} SIP/2.0\r\n"
           "Via: SIP/2.0/UDP kryon:5060;branch=z9hG4bKkryon\r\n"
           "From: <sip:kryon@kryon>;tag=1\r\nTo: <sip:probe@%s>\r\n"
           "Call-ID: kryon-probe\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
           % svc.host).encode("latin-1")
    resp = _udp(svc.host, svc.port, req, 1024)
    if resp and resp[:7] == b"SIP/2.0":
        ua = ""
        for line in resp.split(b"\r\n"):
            if line.lower().startswith((b"user-agent:", b"server:")):
                ua = line.decode("latin-1", "replace")[:60]
                break
        return _f(
            svc, "CWE-200", "MEDIUM", "sip-exposed",
            f"Servidor SIP/VoIP expuesto en {svc.host}:{svc.port} — superficie de enumeración + amplificación por INVITE.",
            f"OPTIONS → respuesta SIP/2.0{(' · ' + ua) if ua else ''}",
            "Restringir SIP a troncales/redes conocidas; fail2ban; deshabilitar respuestas a OPTIONS anónimos.",
        )
    return None


def _check_echo(svc: DiscoveredService) -> Finding | None:
    """echo service (7): reflects whatever you send — legacy simple-TCP/IP reflector."""
    resp = _tcp(svc.host, svc.port, b"kryon-echo-probe", 32)
    if resp and resp[:16] == b"kryon-echo-probe":
        return _f(
            svc, "CWE-406", "LOW", "echo-service-open",
            f"Servicio echo abierto en {svc.host}:{svc.port} — simple-TCP/IP legacy (reflector de amplificación).",
            "Lo enviado fue reflejado intacto",
            "Deshabilitar los simple-TCP/IP services (echo/discard/daytime/chargen); sin uso operativo.",
        )
    return None


# Berkeley r-services: cleartext remote access trusted by source IP / .rhosts.
_RSVC = {
    512: ("rexec", "ejecución remota autenticada por contraseña"),
    513: ("rlogin", "login remoto con confianza por .rhosts/hosts.equiv"),
    514: ("rsh", "shell remoto con confianza por .rhosts/hosts.equiv"),
}


def _check_rservices(svc: DiscoveredService) -> Finding | None:
    """rexec/rlogin/rsh (512-514): legacy Berkeley remote access — cleartext credentials
    and host-trust auth. They wait for client input (no banner), so a successful TCP
    connect is the read-only signal; we send nothing exploitable."""
    name, desc = _RSVC[svc.port]
    try:
        with socket.create_connection((svc.host, svc.port), timeout=DEFAULT_T):
            pass
    except (TimeoutError, OSError):
        return None
    return _f(
        svc, "CWE-319", "HIGH", f"rservice-{name}-exposed",
        f"Servicio r-{name} ({svc.port}/tcp) expuesto en {svc.host} — {desc}, sin cifrado.",
        f"Puerto {svc.port}/tcp accesible = Berkeley r-service ({name}); credenciales y sesión viajan en texto claro.",
        "Deshabilitar rexec/rlogin/rsh (inetd/xinetd) y migrar a SSH; filtrar 512-514 en el perímetro.",
    )


# Port → legacy/IoT detectors.
_LEGACY_PROBES = (
    (lambda s: 6000 <= s.port <= 6005, _check_x11),
    (lambda s: s.port == 623, _check_ipmi),
    (lambda s: s.port == 69, _check_tftp),
    (lambda s: s.port == 631, _check_cups),
    (lambda s: s.port == 47808, _check_bacnet),
    (lambda s: s.port == 79, _check_finger),
    (lambda s: s.port == 7547, _check_tr069),
    (lambda s: s.port == 5060, _check_sip),
    (lambda s: s.port == 7, _check_echo),
    (lambda s: s.port in (512, 513, 514), _check_rservices),
)


def run_legacy_probes(svc: DiscoveredService) -> list[Finding]:
    """Run matching legacy/IoT probes against a discovered service. Never raises."""
    return run_table(svc, _LEGACY_PROBES)
