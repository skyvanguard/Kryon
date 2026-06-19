"""Deterministic network-service detectors — the gap-closers below the existing
``_check_*`` set in engage.py. Each confirms a real, common finding by a READ-ONLY
probe (banca-safe), returns ``Finding`` objects, and degrades to ``None``/[] on any
error so a probe failure never breaks an engagement.

The high-value findings (open Redis/Mongo/Elastic, public SNMP, anonymous FTP) are
the ones that appear in nearly every real network sweep but were not covered: the
DB dispatch only emitted the generic CWE-319 "exposed without TLS", never the
critical CWE-306 "unauthenticated access". These probes confirm the no-auth access.

Imports the data types from engage at module scope; engage imports THESE lazily
inside its dispatch, so there is no import cycle (engage is fully loaded by then).
"""

from __future__ import annotations

import socket
import struct

from kryon.cli.engage import _SEV_RANK, DiscoveredService, Finding

_T = 4.0  # default probe timeout (s)


def _f(svc: DiscoveredService, cwe: str, sev: str, rule_id: str, msg: str, evidence: str, fix: str) -> Finding:
    return Finding(
        cwe=cwe,
        severity=sev,
        host=f"{svc.host}:{svc.port}",
        rule_id=rule_id,
        message=msg,
        evidence=evidence,
        remediation=fix,
        severity_rank=_SEV_RANK[sev],
    )


def _tcp(host: str, port: int, send: bytes = b"", recv: int = 512, timeout: float = _T) -> bytes | None:
    """Open TCP, optionally send, read up to ``recv`` bytes. None on any failure."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if send:
                s.sendall(send)
            return s.recv(recv)
    except (TimeoutError, OSError):
        return None


def _udp(host: str, port: int, payload: bytes, recv: int = 512, timeout: float = _T) -> bytes | None:
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


# ---------------------------------------------------------------------------
# High-value: open data stores (CWE-306 unauthenticated access)
# ---------------------------------------------------------------------------


def _check_redis(svc: DiscoveredService) -> Finding | None:
    """Redis reachable WITHOUT auth. PING returns +PONG when no requirepass;
    -NOAUTH/-ERR when authentication is enforced."""
    resp = _tcp(svc.host, svc.port, b"*1\r\n$4\r\nPING\r\n", 64)
    if resp is None:
        return None
    txt = resp.decode("latin-1", "replace")
    if txt.startswith("+PONG"):
        return _f(
            svc, "CWE-306", "CRITICAL", "redis-noauth",
            f"Redis accesible SIN autenticación en {svc.host}:{svc.port} (respondió PING).",
            f"PING → {txt.strip()!r} (sin requirepass: lectura/escritura completa, posible RCE vía CONFIG SET)",
            "Setear 'requirepass' + bind a loopback/red interna; nunca exponer Redis a internet.",
        )
    return None


def _check_mongodb(svc: DiscoveredService) -> Finding | None:
    """MongoDB reachable WITHOUT auth — uses pymongo (soft dep, graceful skip).
    Confirms by listing databases unauthenticated (read-only)."""
    try:
        from pymongo import MongoClient  # noqa: PLC0415 — soft dep
        from pymongo.errors import OperationFailure, PyMongoError
    except ImportError:
        return None
    try:
        c = MongoClient(svc.host, svc.port, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000)
        dbs = c.list_database_names()  # raises OperationFailure if auth required
        c.close()
    except OperationFailure:
        return None  # auth enforced — safe
    except PyMongoError:
        return None  # unreachable / not mongo
    return _f(
        svc, "CWE-306", "CRITICAL", "mongodb-noauth",
        f"MongoDB accesible SIN autenticación en {svc.host}:{svc.port}.",
        f"list_database_names() sin credenciales devolvió {len(dbs)} DB(s): {dbs[:5]}",
        "Habilitar authorization (security.authorization: enabled) + bind interno.",
    )


def _check_elasticsearch(svc: DiscoveredService) -> Finding | None:
    """Elasticsearch/OpenSearch HTTP API open without auth (200 + cluster JSON)."""
    import urllib.request  # noqa: PLC0415

    for path in ("/_cluster/health", "/"):
        try:
            req = urllib.request.Request(f"http://{svc.host}:{svc.port}{path}", headers={"User-Agent": "kryon"})
            with urllib.request.urlopen(req, timeout=_T) as r:  # noqa: S310 — fixed scheme
                body = r.read(800).decode("latin-1", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return None  # auth enforced — safe
            continue
        except (OSError, ValueError):
            continue
        if any(k in body for k in ('"cluster_name"', '"number_of_nodes"', "You Know, for Search", '"cluster_uuid"')):
            return _f(
                svc, "CWE-306", "CRITICAL", "elasticsearch-open",
                f"Elasticsearch/OpenSearch expuesto SIN auth en {svc.host}:{svc.port}.",
                f"GET {path} → 200 con metadata de cluster (acceso de lectura a todos los índices)",
                "Habilitar security (xpack/opensearch-security) + auth; nunca exponer 9200 a internet.",
            )
    return None


# ---------------------------------------------------------------------------
# High-value: classic exposed services
# ---------------------------------------------------------------------------


def _check_ftp_anon(svc: DiscoveredService) -> Finding | None:
    """Anonymous FTP login allowed (USER anonymous → 230)."""
    try:
        with socket.create_connection((svc.host, svc.port), timeout=_T) as s:
            s.settimeout(_T)
            banner = s.recv(256).decode("latin-1", "replace")
            if not banner.startswith("220"):
                return None
            s.sendall(b"USER anonymous\r\n")
            s.recv(256)
            s.sendall(b"PASS kryon@example.com\r\n")
            resp = s.recv(256).decode("latin-1", "replace")
    except (TimeoutError, OSError):
        return None
    if resp.startswith("230"):
        return _f(
            svc, "CWE-306", "HIGH", "ftp-anonymous",
            f"FTP anónimo habilitado en {svc.host}:{svc.port}.",
            f"USER anonymous / PASS → {resp.strip()!r}",
            "Deshabilitar login anónimo; usar SFTP/FTPS con credenciales.",
        )
    return None


def _check_snmp_public(svc: DiscoveredService) -> Finding | None:
    """SNMP responds to a default community string (public/private). UDP/161."""
    # SNMPv1 GET sysDescr (1.3.6.1.2.1.1.1.0); community bytes patched per attempt.
    for community in (b"public", b"private"):
        pkt = (
            b"\x30" + bytes([0x1d + len(community)])
            + b"\x02\x01\x00\x04" + bytes([len(community)]) + community
            + b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
            + b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        )
        resp = _udp(svc.host, svc.port, pkt, 512)
        if resp and resp[:1] == b"\x30":  # a BER SNMP response sequence
            return _f(
                svc, "CWE-1392", "HIGH", "snmp-default-community",
                f"SNMP responde a la community por defecto '{community.decode()}' en {svc.host}:{svc.port}.",
                f"GET-request con community '{community.decode()}' devolvió respuesta BER ({len(resp)} bytes)",
                "Cambiar las community strings por valores fuertes; preferir SNMPv3 con auth+priv.",
            )
    return None


def _check_telnet(svc: DiscoveredService) -> Finding | None:
    """Telnet exposed (cleartext admin protocol). Negotiation IAC or login prompt."""
    resp = _tcp(svc.host, svc.port, b"", 64)
    if resp is None:
        return None
    if resp[:1] == b"\xff" or b"login:" in resp.lower() or b"username:" in resp.lower():
        return _f(
            svc, "CWE-319", "MEDIUM", "telnet-exposed",
            f"Telnet expuesto en {svc.host}:{svc.port} (protocolo en texto plano).",
            f"Respondió con negociación/banner Telnet ({resp[:16]!r})",
            "Reemplazar Telnet por SSH; cerrar el puerto 23.",
        )
    return None


# ---------------------------------------------------------------------------
# Secondary: handshake-confirmed exposures
# ---------------------------------------------------------------------------


def _check_vnc(svc: DiscoveredService) -> Finding | None:
    """VNC offering the 'None' (type 1) security type = no-auth screen access."""
    try:
        with socket.create_connection((svc.host, svc.port), timeout=_T) as s:
            s.settimeout(_T)
            ver = s.recv(12)
            if not ver.startswith(b"RFB "):
                return None
            s.sendall(ver)  # echo the version to proceed
            data = s.recv(64)
    except (TimeoutError, OSError):
        return None
    # RFB 3.7+: [count][types...]; type 1 == None (no auth)
    if len(data) >= 2 and data[0] >= 1 and 1 in data[1 : 1 + data[0]]:
        return _f(
            svc, "CWE-306", "HIGH", "vnc-noauth",
            f"VNC ofrece acceso SIN autenticación (security type 'None') en {svc.host}:{svc.port}.",
            f"Handshake RFB {ver[4:11].decode('latin-1','replace')} ofreció el tipo de seguridad None",
            "Configurar autenticación VNC + tunelizar sobre SSH/VPN; nunca exponer 5900 directo.",
        )
    return None


def _check_rsync(svc: DiscoveredService) -> Finding | None:
    """rsync daemon exposed (@RSYNCD banner) — often lists modules without auth."""
    resp = _tcp(svc.host, svc.port, b"", 64)
    if resp is None or not resp.startswith(b"@RSYNCD:"):
        return None
    return _f(
        svc, "CWE-306", "MEDIUM", "rsync-daemon-exposed",
        f"Daemon rsync expuesto en {svc.host}:{svc.port}.",
        f"Banner {resp.strip()[:40]!r} (los módulos suelen ser listables/accesibles sin auth)",
        "Requerir 'auth users'+'secrets file' por módulo, o tunelizar rsync sobre SSH.",
    )


def _check_rdp(svc: DiscoveredService) -> Finding | None:
    """RDP exposed; flags missing NLA (CredSSP) which widens the attack surface."""
    cr = bytes.fromhex("030000130ee000000000000100080003000000")
    resp = _tcp(svc.host, svc.port, cr, 64)
    if resp is None or resp[:2] != b"\x03\x00":
        return None
    # X.224 negotiation response (type 0x02) carries the selected protocol;
    # 0x00 = standard RDP security (no NLA), >=0x02 = TLS/CredSSP (NLA).
    nla = len(resp) >= 15 and resp[11] == 0x02 and resp[15] if len(resp) > 15 else 0
    if not nla:
        return _f(
            svc, "CWE-287", "MEDIUM", "rdp-no-nla",
            f"RDP expuesto sin NLA (Network Level Authentication) en {svc.host}:{svc.port}.",
            f"Negociación X.224 respondió sin requerir CredSSP/TLS ({resp[:20].hex()})",
            "Forzar NLA + restringir RDP a VPN/jump-host; aplicar parches (BlueKeep CVE-2019-0708).",
        )
    return _f(
        svc, "CWE-200", "LOW", "rdp-exposed",
        f"RDP expuesto en {svc.host}:{svc.port} (con NLA).",
        "Servicio RDP alcanzable; superficie de ataque/brute-force.",
        "Restringir RDP a VPN/jump-host aunque tenga NLA.",
    )


def _check_postgres_trust(svc: DiscoveredService) -> Finding | None:
    """PostgreSQL with 'trust' auth — connects with NO password (AuthenticationOk)."""
    params = b"user\x00postgres\x00database\x00postgres\x00\x00"
    body = struct.pack(">I", 0x00030000) + params
    startup = struct.pack(">I", len(body) + 4) + body
    try:
        with socket.create_connection((svc.host, svc.port), timeout=_T) as s:
            s.settimeout(_T)
            s.sendall(startup)
            resp = s.recv(32)
    except (TimeoutError, OSError):
        return None
    # 'R' (Authentication) + len(8) + authtype; 0 == AuthenticationOk (trust, no pw)
    if len(resp) >= 9 and resp[:1] == b"R" and struct.unpack(">I", resp[5:9])[0] == 0:
        return _f(
            svc, "CWE-306", "CRITICAL", "postgres-trust-auth",
            f"PostgreSQL acepta conexión SIN contraseña (auth 'trust') en {svc.host}:{svc.port}.",
            "StartupMessage user=postgres → AuthenticationOk (sin password)",
            "Cambiar pg_hba.conf de 'trust' a 'scram-sha-256'; bind interno.",
        )
    return None


def _check_ntp_monlist(svc: DiscoveredService) -> Finding | None:
    """NTP monlist (mode 7) enabled — DDoS amplification vector. UDP/123."""
    monlist = b"\x17\x00\x03\x2a" + b"\x00" * 4
    resp = _udp(svc.host, svc.port, monlist, 512)
    if resp and len(resp) > 8:
        return _f(
            svc, "CWE-406", "MEDIUM", "ntp-monlist",
            f"NTP responde a monlist (mode 7) en {svc.host}:{svc.port} — vector de amplificación DDoS.",
            f"Request monlist devolvió {len(resp)} bytes (factor de amplificación alto)",
            "Deshabilitar 'monlist' (noquery) o actualizar ntpd >= 4.2.7p26.",
        )
    return None


def _check_smtp(svc: DiscoveredService) -> Finding | None:
    """SMTP offering AUTH over cleartext (no STARTTLS) — credential exposure."""
    try:
        with socket.create_connection((svc.host, svc.port), timeout=_T) as s:
            s.settimeout(_T)
            if not s.recv(256).startswith(b"220"):
                return None
            s.sendall(b"EHLO kryon.local\r\n")
            caps = s.recv(512).decode("latin-1", "replace")
    except (TimeoutError, OSError):
        return None
    has_auth = "AUTH" in caps.upper()
    has_tls = "STARTTLS" in caps.upper()
    if has_auth and not has_tls:
        return _f(
            svc, "CWE-319", "MEDIUM", "smtp-cleartext-auth",
            f"SMTP ofrece AUTH sin STARTTLS en {svc.host}:{svc.port} (credenciales en texto plano).",
            "EHLO anunció AUTH pero no STARTTLS",
            "Habilitar STARTTLS y rechazar AUTH sobre conexiones no cifradas.",
        )
    return None


def _check_ldap_anon(svc: DiscoveredService) -> Finding | None:
    """LDAP anonymous bind allowed (bindRequest empty DN+pw → success resultCode 0)."""
    # LDAPv3 anonymous bindRequest, messageID 1
    bind = bytes.fromhex("300c020101600702010104008000")
    resp = _tcp(svc.host, svc.port, bind, 32)
    if resp is None or resp[:1] != b"\x30":
        return None
    # bindResponse (app 1 = 0x61) carrying enumerated resultCode 0x00 (success)
    if b"\x61" in resp and b"\x0a\x01\x00" in resp:
        return _f(
            svc, "CWE-287", "MEDIUM", "ldap-anonymous-bind",
            f"LDAP permite bind anónimo en {svc.host}:{svc.port}.",
            "bindRequest con DN/password vacíos → resultCode success (0)",
            "Deshabilitar bind anónimo (dsHeuristics / -allow-anonymous-bind off).",
        )
    return None


def _check_nfs_rpcbind(svc: DiscoveredService) -> Finding | None:
    """rpcbind/portmapper (111) exposed; flags NFS/mountd registered = exported FS.
    portmap v2 DUMP (proc 4) over TCP — read-only, lists registered RPC programs."""
    call = (
        b"\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x02"  # XID, CALL, rpcvers 2
        b"\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04"  # prog 100000, vers 2, proc 4 (DUMP)
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # cred null
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # verf null
    )
    framed = struct.pack(">I", 0x80000000 | len(call)) + call  # TCP RPC record marker
    resp = _tcp(svc.host, svc.port, framed, 4096)
    if resp is None or len(resp) < 24:
        return None
    # NFS = 100003 (0x000186a3), mountd = 100005 (0x000186a5)
    if b"\x00\x01\x86\xa3" in resp or b"\x00\x01\x86\xa5" in resp:
        return _f(
            svc, "CWE-306", "HIGH", "nfs-exposed",
            f"NFS/mountd registrado en rpcbind expuesto en {svc.host}:{svc.port}.",
            "portmap DUMP listó el programa NFS (100003)/mountd (100005) — exports accesibles vía showmount",
            "Restringir exports (no_root_squash off, allowlist de hosts) + firewall a 111/2049/mountd.",
        )
    return _f(
        svc, "CWE-200", "LOW", "rpcbind-exposed",
        f"rpcbind/portmapper expuesto en {svc.host}:{svc.port} (enumeración de servicios RPC).",
        f"portmap DUMP devolvió {len(resp)} bytes con programas registrados",
        "Firewall a 111; deshabilitar rpcbind si no se usa NFS/NIS.",
    )


def _check_mssql(svc: DiscoveredService) -> Finding | None:
    """MSSQL exposed — TDS pre-login confirms the engine and leaks the version."""
    payload = bytes.fromhex("0000001a0006010020000102002100010300220004ff")
    version = b"\x00" * 6 + b"\x00"
    body = payload + version
    pkt = struct.pack(">BBH", 0x12, 0x01, len(body) + 8) + b"\x00\x00\x00\x00" + body
    resp = _tcp(svc.host, svc.port, pkt, 256)
    if resp is None or resp[:1] != b"\x04":  # TDS server response packet
        return None
    # The VERSION token payload (major.minor) sits just past the option table.
    ver = f"{resp[10]}.{resp[11]}" if len(resp) > 11 else ""
    return _f(
        svc, "CWE-200", "LOW", "mssql-exposed",
        f"Microsoft SQL Server expuesto en {svc.host}:{svc.port} (TDS responde al pre-login).",
        f"Pre-login TDS respondió{(' versión ~' + ver) if ver else ''} — superficie de brute-force/CVE",
        "Restringir 1433 a red interna/VPN; forzar Force Encryption; deshabilitar sa o usar password fuerte.",
    )


# ---------------------------------------------------------------------------
# Dispatch table consumed by engage / investigate: (matcher) -> detector
# Matcher receives the DiscoveredService; True = run that detector.
# ---------------------------------------------------------------------------

PROBES: tuple[tuple[str, object, object], ...] = (
    ("redis", lambda s: s.service == "redis" or s.port == 6379, _check_redis),
    ("mongodb", lambda s: s.service == "mongodb" or s.port == 27017, _check_mongodb),
    ("elasticsearch", lambda s: s.port in (9200, 9201), _check_elasticsearch),
    ("ftp", lambda s: s.service == "ftp" or s.port == 21, _check_ftp_anon),
    ("snmp", lambda s: s.service == "snmp" or s.port == 161, _check_snmp_public),
    ("telnet", lambda s: s.service == "telnet" or s.port == 23, _check_telnet),
    ("vnc", lambda s: s.service in ("vnc", "vnc-http") or 5900 <= s.port <= 5905, _check_vnc),
    ("rsync", lambda s: s.service == "rsync" or s.port == 873, _check_rsync),
    ("rdp", lambda s: s.service in ("ms-wbt-server", "rdp") or s.port == 3389, _check_rdp),
    ("postgres", lambda s: s.service in ("postgresql", "postgres") or s.port == 5432, _check_postgres_trust),
    ("ntp", lambda s: s.service == "ntp" or s.port == 123, _check_ntp_monlist),
    ("smtp", lambda s: s.service in ("smtp", "submission") or s.port in (25, 587), _check_smtp),
    ("ldap", lambda s: s.service in ("ldap", "ldaps") or s.port in (389, 636), _check_ldap_anon),
    ("nfs", lambda s: s.service in ("rpcbind", "nfs", "portmapper") or s.port == 111, _check_nfs_rpcbind),
    ("mssql", lambda s: s.service in ("ms-sql-s", "ms-sql") or s.port == 1433, _check_mssql),
)


def run_service_probes(svc: DiscoveredService) -> list[Finding]:
    """Run every matching probe against a discovered service. Never raises."""
    out: list[Finding] = []
    for _name, matches, probe in PROBES:
        try:
            if matches(svc):
                f = probe(svc)
                if f:
                    out.append(f)
        except Exception:  # noqa: BLE001 — a probe must never break the sweep
            continue
    return out
