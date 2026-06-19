"""Batch P — ICS/SCADA/OT exposure. Wires the already-validated read-only OT
probes from ``kryon.tools.ot`` (Modbus/S7comm/IEC-104/DNP3) into the engage
dispatch — they existed but were never reachable from a normal engage/investigate
sweep — and adds EtherNet/IP, OPC-UA, Veeder-Root ATG, and Niagara Fox.

SAFETY (OT is the one place a probe can move the physical world): every probe
here is an IDENTIFICATION read only. We never send a write/control function code
(Modbus 5/6/15/16, DNP3 Direct-Operate, IEC-104 I-frames). The underlying tools
keep writes behind an opt-in flag we never set. Confirmed by protocol response.
"""

from __future__ import annotations

import struct

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _tcp

_T = 5.0


# --------------------------------------------------------------------------
# Wire the existing, validated kryon.tools.ot probes (read-only by default)
# --------------------------------------------------------------------------


def _check_modbus(svc: DiscoveredService) -> Finding | None:
    from kryon.tools.ot.modbus_scan import modbus_scan  # noqa: PLC0415

    r = modbus_scan(svc.host, port=svc.port)  # attempt_write stays False
    if not (r.reachable and r.has_unauth_exposure):
        return None
    vendor = r.device_identification.get("VendorName") or r.device_identification.get("vendor", "")
    return _f(svc, "CWE-306", "HIGH", "modbus-unauth",
              f"Modbus/TCP sin autenticación en {svc.host}:{svc.port} — PLC controlable desde IT.",
              f"Read Coils/Holding (FC 1/3) respondidos sin auth{(' · vendor=' + vendor) if vendor else ''}",
              "Segmentar la red OT (sin ruteo IT/internet); firewall industrial; Modbus solo en VLAN de control.")


def _check_s7comm(svc: DiscoveredService) -> Finding | None:
    from kryon.tools.ot.s7_enum import s7_enum  # noqa: PLC0415

    r = s7_enum(svc.host, port=svc.port)
    if not (r.reachable and r.has_unauth_exposure):
        return None
    fw = r.plc_firmware_version or r.module_identification.get("module", "")
    return _f(svc, "CWE-306", "HIGH", "s7comm-unauth",
              f"Siemens S7comm sin autenticación en {svc.host}:{svc.port} — sesión S7 anónima.",
              f"COTP connect + S7 Setup ack sin challenge{(' · fw=' + fw) if fw else ''} (ReadSZL read-only)",
              "Activar S7 'connection mechanism' con password; segmentar la red OT; deshabilitar acceso IT.")


def _check_iec104(svc: DiscoveredService) -> Finding | None:
    from kryon.tools.ot.iec104_probe import iec104_probe  # noqa: PLC0415

    r = iec104_probe(svc.host, port=svc.port)
    if not (r.reachable and r.has_unauth_exposure):
        return None
    return _f(svc, "CWE-306", "HIGH", "iec104-unauth",
              f"IEC 60870-5-104 sin autenticación en {svc.host}:{svc.port} — RTU/SCADA de telecontrol expuesto.",
              "STARTDT activación confirmada sin auth previa (control-frame read-only, sin I-frames)",
              "Segmentar telecontrol (IEC 62443); VPN/IPsec para enlaces remotos; nunca exponer 2404 a IT/WAN.")


def _check_dnp3(svc: DiscoveredService) -> Finding | None:
    from kryon.tools.ot.dnp3_probe import dnp3_probe  # noqa: PLC0415

    r = dnp3_probe(svc.host, port=svc.port)
    if not (r.reachable and r.has_unauth_exposure):
        return None
    return _f(svc, "CWE-306", "HIGH", "dnp3-unauth",
              f"DNP3 sin Secure Authentication v5 en {svc.host}:{svc.port} — outstation legible sin challenge.",
              "Read Class 0 respondido sin desafío SAv5 (sin write probes)",
              "Habilitar DNP3 Secure Authentication v5 (IEEE 1815); segmentar (NERC CIP-005); no exponer 20000.")


# --------------------------------------------------------------------------
# New protocols (read-only identification requests)
# --------------------------------------------------------------------------


def _check_enip(svc: DiscoveredService) -> Finding | None:
    """EtherNet/IP List Identity (cmd 0x0063) — reads device identity only."""
    pkt = struct.pack("<HHIIQ", 0x0063, 0, 0, 0, 0) + b"\x00\x00\x00\x00"  # 24-byte encap header
    resp = _tcp(svc.host, svc.port, pkt, 256)
    if resp and len(resp) >= 24 and resp[:2] == b"\x63\x00":  # List Identity reply echoed
        return _f(svc, "CWE-306", "HIGH", "enip-exposed",
                  f"EtherNet/IP (CIP) expuesto en {svc.host}:{svc.port} — PLC/IO Rockwell/Allen-Bradley alcanzable desde IT.",
                  "List Identity (0x63) respondido (identidad del device, read-only)",
                  "Segmentar la red OT; CIP Security donde sea posible; nunca exponer 44818 a IT/internet.")
    return None


def _check_opcua(svc: DiscoveredService) -> Finding | None:
    """OPC-UA reachable: a HELlo handshake gets an ACKnowledge (read-only)."""
    url = f"opc.tcp://{svc.host}:{svc.port}".encode("latin-1")
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, len(url)) + url  # ver, recv, send, maxmsg, urllen
    msg = b"HELF" + struct.pack("<I", 8 + len(body)) + body
    resp = _tcp(svc.host, svc.port, msg, 64)
    if resp and resp[:3] == b"ACK":
        return _f(svc, "CWE-306", "MEDIUM", "opcua-exposed",
                  f"Servidor OPC-UA expuesto en {svc.host}:{svc.port} — verificar SecurityMode=None / token Anonymous.",
                  "HEL → ACK (handshake OPC-UA respondido)",
                  "Exigir SecurityMode SignAndEncrypt + auth no-anónima; segmentar la red OT; restringir 4840.")
    return None


def _check_atg(svc: DiscoveredService) -> Finding | None:
    """Veeder-Root / Guardian-AST tank gauge: I20100 = in-tank inventory (read-only)."""
    resp = _tcp(svc.host, svc.port, b"\x01I20100\r", 512)
    if resp and (b"I20100" in resp or b"IN-TANK" in resp.upper()):
        return _f(svc, "CWE-306", "HIGH", "atg-exposed",
                  f"Tank gauge ATG (Veeder-Root) expuesto en {svc.host}:{svc.port} — inventario/control de combustible.",
                  "Comando I20100 → reporte de inventario in-tank (read-only; nunca se emiten S-commands)",
                  "Nunca exponer el ATG a internet; ACL a la consola de monitoreo; firmware al día.")
    return None


def _check_niagara_fox(svc: DiscoveredService) -> Finding | None:
    """Tridium Niagara Fox: hello query → banner with fox.version/station/hostId."""
    hello = b"fox a:0 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"
    resp = _tcp(svc.host, svc.port, hello, 1024)
    if resp and (b"fox." in resp or b"station.name" in resp or b"niagara" in resp.lower()):
        return _f(svc, "CWE-200", "HIGH", "niagara-fox-exposed",
                  f"Controlador Niagara/Tridium (Fox) expuesto en {svc.host}:{svc.port} — automatización de edificios (BAS).",
                  "Query 'fox hello' → banner (fox.version/station.name/hostId)",
                  "Restringir Fox (1911/4911) a la red de gestión BAS; credenciales fuertes; firmware al día.")
    return None


_OT_PROBES = (
    (lambda s: s.port == 502, _check_modbus),
    (lambda s: s.port == 102, _check_s7comm),
    (lambda s: s.port == 2404, _check_iec104),
    (lambda s: s.port == 20000, _check_dnp3),
    (lambda s: s.port in (44818, 2222), _check_enip),
    (lambda s: s.port == 4840, _check_opcua),
    (lambda s: s.port == 10001, _check_atg),
    (lambda s: s.port in (1911, 4911), _check_niagara_fox),
)


def run_ot_probes(svc: DiscoveredService) -> list[Finding]:
    """Run matching ICS/SCADA/OT identification probes (read-only). Never raises."""
    out: list[Finding] = []
    for matches, probe in _OT_PROBES:
        try:
            if matches(svc):
                f = probe(svc)
                if f:
                    out.append(f)
        except Exception:  # noqa: BLE001 — a probe (or a missing tools.ot dep) must never break the sweep
            continue
    return out
