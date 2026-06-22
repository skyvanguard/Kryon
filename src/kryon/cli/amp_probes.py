"""Batch L — UDP reflector / amplification + info-leak posture for services not
already covered by the Batch-A amplifiers (SSDP/CharGen/NTP/SNMP): open DNS
resolver, memcached over UDP, NetBIOS name service, and mDNS. Each sends ONE
small UDP probe and checks for a response (read-only recon, never an attack).

Imports utilities from service_probes (one-way; engage imports the probe modules
lazily, so no import cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import _f, _udp, run_table


def _dns_query(qname: str, qtype: int = 1) -> bytes:
    header = b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id, RD flag, qd=1
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split(".")) + b"\x00"
    return header + q + qtype.to_bytes(2, "big") + b"\x00\x01"  # qtype, qclass IN


def _check_dns_open_resolver(svc: DiscoveredService) -> Finding | None:
    """Recursive query for an external name succeeds → open resolver (DDoS
    amplification reflector + DNS cache-poisoning exposure)."""
    resp = _udp(svc.host, svc.port, _dns_query("dns.google"), 512)
    if resp and len(resp) >= 12:
        ra = resp[3] & 0x80  # Recursion Available
        rcode = resp[3] & 0x0F
        ancount = int.from_bytes(resp[6:8], "big")
        if ra and rcode == 0 and ancount > 0:
            return _f(
                svc, "CWE-406", "MEDIUM", "dns-open-resolver",
                f"Resolver DNS abierto en {svc.host}:{svc.port}/udp — reflector de amplificación DDoS + cache poisoning.",
                "Query recursiva externa (dns.google) respondida con RA + answers",
                "Deshabilitar la recursión para clientes externos (allow-recursion a la red interna); BCP38.",
            )
    return None


def _check_memcached_udp(svc: DiscoveredService) -> Finding | None:
    """memcached reachable over UDP → notorious amplification reflector (factor ~10000x)."""
    pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"  # UDP frame header + stats
    resp = _udp(svc.host, svc.port, pkt, 1024)
    if resp and b"STAT " in resp:
        return _f(
            svc, "CWE-406", "HIGH", "memcached-udp-amplification",
            f"memcached responde por UDP en {svc.host}:{svc.port} — reflector de amplificación (CVE-2018-1000115).",
            "stats por UDP → respuesta con líneas STAT",
            "Deshabilitar el listener UDP (-U 0); bind a 127.0.0.1; firewall del puerto 11211.",
        )
    return None


def _check_netbios_ns(svc: DiscoveredService) -> Finding | None:
    """NetBIOS Name Service node-status (NBSTAT '*') → leaks hostname/domain/MAC + amplifies."""
    pkt = (
        b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"  # encoded wildcard "*"
        b"\x00\x21\x00\x01"  # qtype NBSTAT, class IN
    )
    resp = _udp(svc.host, svc.port, pkt, 512)
    if resp and len(resp) >= 12 and resp[:2] == b"\xa2\x48":  # our trans-id echoed
        return _f(
            svc, "CWE-200", "MEDIUM", "netbios-ns-exposed",
            f"NetBIOS Name Service expuesto en {svc.host}:{svc.port}/udp — filtra hostname/dominio/MAC + amplifica.",
            "NBSTAT node-status → tabla de nombres NetBIOS",
            "Deshabilitar NetBIOS over TCP/IP donde no se use; filtrar 137/udp en el perímetro.",
        )
    return None


def _check_mdns(svc: DiscoveredService) -> Finding | None:
    """mDNS responder reachable off-link → service/host enumeration + amplification."""
    qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"  # PTR, IN
    resp = _udp(svc.host, svc.port, pkt, 1024)
    if resp and len(resp) >= 12 and (resp[2] & 0x80):  # QR response bit set
        return _f(
            svc, "CWE-200", "LOW", "mdns-exposed",
            f"mDNS responde en {svc.host}:{svc.port}/udp fuera de la red local — enumeración de servicios/hosts.",
            "Query _services._dns-sd._udp.local → respuesta mDNS",
            "Restringir mDNS a la red local (no rutear 5353/udp); deshabilitar si no se usa.",
        )
    return None


# CLDAP rootDSE searchRequest (messageID 1, baseObject "", scope base, filter
# present=objectClass, no attributes) — the canonical amplification probe.
_CLDAP_PROBE = bytes.fromhex(
    "30840000002d"          # SEQUENCE (len 45)
    "020101"                # messageID = 1
    "63840000 0024"         # [APPLICATION 3] searchRequest (len 36)
    "0400"                  # baseObject ""
    "0a0100"                # scope = baseObject
    "0a0100"                # derefAliases = never
    "020100"                # sizeLimit = 0
    "020100"                # timeLimit = 0
    "010100"                # typesOnly = false
    "870b 6f626a656374436c617373"  # filter present = "objectClass"
    "3084 00000000".replace(" ", "")  # attributes = {}
)


def _check_cldap(svc: DiscoveredService) -> Finding | None:
    """CLDAP (connectionless LDAP over UDP) responds to a rootDSE query → DDoS
    amplification reflector (classic on exposed Active Directory domain controllers)."""
    resp = _udp(svc.host, svc.port, _CLDAP_PROBE, 1024)
    if resp and len(resp) >= 2 and resp[0] == 0x30:  # an LDAP message (SEQUENCE) came back
        return _f(
            svc, "CWE-406", "MEDIUM", "cldap-amplification",
            f"CLDAP responde por UDP en {svc.host}:{svc.port} — reflector de amplificación DDoS (típico en AD DCs).",
            "searchRequest rootDSE (UDP) → respuesta LDAP",
            "Filtrar 389/udp en el perímetro; los DC sólo necesitan CLDAP en la red interna.",
        )
    return None


def _check_rpcbind_udp(svc: DiscoveredService) -> Finding | None:
    """rpcbind/portmapper DUMP over UDP → lists every RPC program (NFS/mountd/etc)
    and is a ~28x amplification reflector."""
    xid = b"rkyn"
    call = (xid + b"\x00\x00\x00\x00\x00\x00\x00\x02"  # CALL, rpcvers 2
            b"\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04"  # prog 100000, vers 2, proc 4 (DUMP)
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")  # null cred + verf
    resp = _udp(svc.host, svc.port, call, 1024)
    if resp and len(resp) >= 8 and resp[:4] == xid and resp[4:8] == b"\x00\x00\x00\x01":  # REPLY
        return _f(svc, "CWE-406", "MEDIUM", "rpcbind-udp-amplification",
                  f"rpcbind/portmapper responde por UDP en {svc.host}:{svc.port} — reflector de amplificación (~28x) + lista de servicios RPC.",
                  "PMAPPROC_DUMP (UDP) → reply con la tabla de programas RPC",
                  "Filtrar 111/udp en el perímetro; usar rpcbind -w + restricciones; preferir NFSv4 (sin portmapper).")
    return None


def _check_coap(svc: DiscoveredService) -> Finding | None:
    """CoAP responder (5683/udp): GET /.well-known/core → IoT amplification reflector."""
    pkt = b"\x40\x01\x12\x34\xbb.well-known\x04core"
    resp = _udp(svc.host, svc.port, pkt, 1024)
    if resp and len(resp) >= 4 and (resp[0] & 0xC0) == 0x40 and (resp[1] >> 5) == 2:  # CoAP 2.xx response
        return _f(svc, "CWE-406", "MEDIUM", "coap-amplification",
                  f"CoAP responde por UDP en {svc.host}:{svc.port} — dispositivo IoT + reflector de amplificación.",
                  "GET /.well-known/core → respuesta CoAP 2.xx",
                  "Restringir CoAP a la red IoT; usar DTLS; filtrar 5683/udp en el perímetro.")
    return None


def _check_ripv1(svc: DiscoveredService) -> Finding | None:
    """RIPv1 (520/udp): a request gets the full routing table — high (~131x) amplification."""
    req = b"\x01\x01\x00\x00\x00\x00\x00\x00" + b"\x00" * 12 + b"\x00\x00\x00\x10"  # request, AFI 0, metric 16
    resp = _udp(svc.host, svc.port, req, 1024)
    if resp and len(resp) >= 4 and resp[0] == 0x02 and resp[1] == 0x01:  # RIPv1 response
        return _f(svc, "CWE-406", "MEDIUM", "ripv1-amplification",
                  f"RIPv1 expuesto en {svc.host}:{svc.port} — protocolo de ruteo sin auth + reflector (~131x).",
                  "RIP request → response con la tabla de rutas",
                  "Deshabilitar RIPv1 (usar OSPF/RIPv2 con auth); filtrar 520/udp; no anunciar rutas a redes no confiables.")
    return None


def _check_qotd(svc: DiscoveredService) -> Finding | None:
    """QOTD (17/udp): empty datagram → quote text; classic ~140x amplifier."""
    resp = _udp(svc.host, svc.port, b"\r\n", 512)
    if resp and len(resp) > 2:
        return _f(svc, "CWE-406", "LOW", "qotd-amplification",
                  f"QOTD (Quote of the Day) abierto en {svc.host}:{svc.port}/udp — reflector de amplificación (~140x).",
                  f"Datagrama vacío → respuesta de {len(resp)} bytes",
                  "Deshabilitar el servicio simple-TCP/IP 'qotd' (inutil operativamente); filtrar 17/udp.")
    return None


def _check_wsdiscovery(svc: DiscoveredService) -> Finding | None:
    """WS-Discovery (3702/udp) Probe → ProbeMatches; device enumeration + amplification."""
    probe = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        b'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        b'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        b'<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
        b'<a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID>'
        b'<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>'
        b'<s:Body><d:Probe/></s:Body></s:Envelope>'
    )
    resp = _udp(svc.host, svc.port, probe, 2048)
    if resp and (b"ProbeMatches" in resp or b"XAddrs" in resp):
        return _f(svc, "CWE-406", "LOW", "wsdiscovery-exposed",
                  f"WS-Discovery responde por UDP en {svc.host}:{svc.port} — enumeración de dispositivos + reflector de amplificación.",
                  "Probe → ProbeMatches (URLs de servicios del device expuestas)",
                  "Filtrar 3702/udp en el perímetro; deshabilitar WS-Discovery en dispositivos expuestos.")
    return None


_AMP_PROBES = (
    (lambda s: s.port == 53, _check_dns_open_resolver),
    (lambda s: s.port == 11211, _check_memcached_udp),
    (lambda s: s.port == 137, _check_netbios_ns),
    (lambda s: s.port == 5353, _check_mdns),
    (lambda s: s.port == 389, _check_cldap),
    (lambda s: s.port == 111, _check_rpcbind_udp),
    (lambda s: s.port == 5683, _check_coap),
    (lambda s: s.port == 520, _check_ripv1),
    (lambda s: s.port == 17, _check_qotd),
    (lambda s: s.port == 3702, _check_wsdiscovery),
)


def run_amp_probes(svc: DiscoveredService) -> list[Finding]:
    """Run matching UDP reflector / info-leak probes. Never raises."""
    return run_table(svc, _AMP_PROBES)
