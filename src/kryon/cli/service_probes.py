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


def _http_get(host: str, port: int, path: str, scheme: str = "http", auth: str = "") -> tuple[int, str] | None:
    """GET a path; return (status, body[:4000]) or None on connection error. 401/403
    surface as their status so callers can tell "auth enforced" from "open"."""
    import base64  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    headers = {"User-Agent": "kryon-probe"}
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    try:
        req = urllib.request.Request(f"{scheme}://{host}:{port}{path}", headers=headers)
        ctx = None
        if scheme == "https":
            import ssl  # noqa: PLC0415

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=_T, context=ctx) as r:  # noqa: S310 — fixed scheme
            return r.status, r.read(4000).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(2000).decode("latin-1", "replace")
        except Exception:  # noqa: BLE001
            return e.code, ""
    except (OSError, ValueError):
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
# Open data stores / infra services (HTTP + TCP), CWE-306 unauthenticated access
# ---------------------------------------------------------------------------


def _check_memcached(svc: DiscoveredService) -> Finding | None:
    """Memcached reachable without auth (stats returns STAT lines). Also a UDP
    amplification vector when 11211/udp answers."""
    resp = _tcp(svc.host, svc.port, b"stats\r\n", 512)
    if resp and resp.startswith(b"STAT "):
        amp = _udp(svc.host, svc.port, b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n", 1024)
        extra = " + responde por UDP (amplificación DDoS)" if amp else ""
        return _f(
            svc, "CWE-306", "HIGH", "memcached-noauth",
            f"Memcached accesible SIN autenticación en {svc.host}:{svc.port}{extra}.",
            f"stats → {resp[:40]!r} (lectura/escritura de cache sin auth; SASL off)",
            "Habilitar SASL + bind interno; deshabilitar UDP (-U 0) para cortar la amplificación.",
        )
    return None


def _check_zookeeper(svc: DiscoveredService) -> Finding | None:
    """Zookeeper four-letter command 'stat' answers without auth (info leak)."""
    resp = _tcp(svc.host, svc.port, b"stat", 512)
    if resp and (b"Zookeeper version" in resp or b"Clients:" in resp):
        return _f(
            svc, "CWE-306", "MEDIUM", "zookeeper-noauth",
            f"Zookeeper responde a comandos 4lw sin auth en {svc.host}:{svc.port}.",
            f"stat → {resp[:60]!r} (config de cluster, clientes conectados)",
            "Restringir 4lw.commands.whitelist + ACLs + firewall a 2181.",
        )
    return None


def _check_couchdb(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/_all_dbs")
    if r and r[0] == 200 and (r[1].startswith("[") or "_users" in r[1]):
        return _f(
            svc, "CWE-306", "CRITICAL", "couchdb-open",
            f"CouchDB expuesto SIN auth en {svc.host}:{svc.port}.",
            f"GET /_all_dbs → 200 listó las bases: {r[1][:80]}",
            "Setear admin (require_valid_user=true) + bind interno.",
        )
    return None


def _check_etcd(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/version")
    if r and r[0] == 200 and "etcdserver" in r[1]:
        return _f(
            svc, "CWE-306", "CRITICAL", "etcd-open",
            f"etcd expuesto SIN auth en {svc.host}:{svc.port} (a menudo guarda secrets de Kubernetes).",
            f"GET /version → {r[1][:80]}",
            "Habilitar client cert auth (--client-cert-auth) + bind a 127.0.0.1/peers.",
        )
    return None


def _check_consul(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/v1/catalog/services")
    if r and r[0] == 200 and r[1].lstrip().startswith("{"):
        return _f(
            svc, "CWE-306", "HIGH", "consul-open",
            f"Consul API/UI expuesto SIN ACL en {svc.host}:{svc.port}.",
            f"GET /v1/catalog/services → 200 con el catálogo: {r[1][:80]}",
            "Habilitar ACLs (default deny) + TLS + bind interno.",
        )
    return None


def _check_solr(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/solr/admin/info/system?wt=json")
    if r and r[0] == 200 and ("lucene" in r[1] or "solr_home" in r[1]):
        return _f(
            svc, "CWE-306", "HIGH", "solr-open",
            f"Apache Solr admin expuesto SIN auth en {svc.host}:{svc.port}.",
            "GET /solr/admin/info/system → 200 (Solr admin abierto — históricamente RCE vía VelocityResponseWriter/config)",
            "Habilitar autenticación (BasicAuth plugin) + bind interno; deshabilitar config edits remotos.",
        )
    return None


def _check_influxdb(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/query?q=SHOW+DATABASES")
    if r and r[0] == 200 and '"results"' in r[1]:
        return _f(
            svc, "CWE-306", "HIGH", "influxdb-open",
            f"InfluxDB expuesto SIN auth en {svc.host}:{svc.port}.",
            f"GET /query?q=SHOW DATABASES → 200 con resultados: {r[1][:80]}",
            "Setear auth-enabled=true + usuarios; bind interno.",
        )
    return None


def _check_clickhouse(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/?query=SELECT+1")
    if r and r[0] == 200 and r[1].strip() == "1":
        return _f(
            svc, "CWE-306", "HIGH", "clickhouse-open",
            f"ClickHouse HTTP expuesto SIN auth en {svc.host}:{svc.port}.",
            "GET /?query=SELECT 1 → 200 '1' (default user sin password)",
            "Setear password al user default + bind interno + readonly donde aplique.",
        )
    return None


def _check_rabbitmq_mgmt(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/api/overview", auth="guest:guest")
    if r and r[0] == 200 and "rabbitmq_version" in r[1]:
        return _f(
            svc, "CWE-1392", "HIGH", "rabbitmq-default-creds",
            f"RabbitMQ management con credenciales por defecto guest:guest en {svc.host}:{svc.port}.",
            "GET /api/overview con guest:guest → 200",
            "Borrar/cambiar el usuario guest; restringir el plugin de management a red interna.",
        )
    return None


# ---------------------------------------------------------------------------
# Container / orchestration — CRITICAL: unauthenticated = host/cluster takeover
# ---------------------------------------------------------------------------


def _check_docker_api(svc: DiscoveredService) -> Finding | None:
    for scheme in ("http", "https"):
        r = _http_get(svc.host, svc.port, "/version", scheme=scheme)
        if r and r[0] == 200 and '"ApiVersion"' in r[1] and ('"GoVersion"' in r[1] or '"Os"' in r[1]):
            return _f(
                svc, "CWE-306", "CRITICAL", "docker-api-exposed",
                f"Docker Engine API expuesta SIN auth en {svc.host}:{svc.port}.",
                f"GET /version ({scheme}) → 200 con metadata de Docker — equivale a RCE root del host (run -v /:/host)",
                "Nunca exponer 2375; usar el socket local o 2376 con TLS mutuo (--tlsverify).",
            )
    return None


def _check_kubelet(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/pods", scheme="https")
    if r and r[0] == 200 and ('"PodList"' in r[1] or '"kind"' in r[1]):
        return _f(
            svc, "CWE-306", "CRITICAL", "kubelet-anonymous",
            f"Kubelet permite acceso anónimo a /pods en {svc.host}:{svc.port}.",
            "GET https:///pods → 200 con PodList (acceso a /exec, /run → RCE en pods)",
            "Setear --anonymous-auth=false + --authorization-mode=Webhook en el kubelet.",
        )
    return None


def _check_k8s_api(svc: DiscoveredService) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/api/v1/namespaces", scheme="https")
    if r and r[0] == 200 and '"NamespaceList"' in r[1]:
        return _f(
            svc, "CWE-306", "CRITICAL", "k8s-api-anonymous",
            f"Kubernetes API server permite acceso anónimo en {svc.host}:{svc.port}.",
            "GET https:///api/v1/namespaces → 200 (anonymous tiene RBAC sobre recursos del cluster)",
            "Quitar bindings de system:anonymous/system:unauthenticated; --anonymous-auth=false.",
        )
    ver = _http_get(svc.host, svc.port, "/version", scheme="https")
    if ver and ver[0] == 200 and '"gitVersion"' in ver[1]:
        return _f(
            svc, "CWE-200", "LOW", "k8s-api-exposed",
            f"Kubernetes API server alcanzable en {svc.host}:{svc.port} (versión expuesta).",
            f"GET /version → {ver[1][:80]}",
            "Restringir el API server a red de management/VPN.",
        )
    return None


# ---------------------------------------------------------------------------
# UDP amplification vectors (DDoS — compliance + reputational risk)
# ---------------------------------------------------------------------------


def _check_ssdp(svc: DiscoveredService) -> Finding | None:
    msearch = (
        b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
        b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    )
    resp = _udp(svc.host, svc.port, msearch, 1024)
    if resp and (b"HTTP/1.1 200" in resp or b"ST:" in resp):
        return _f(
            svc, "CWE-406", "MEDIUM", "ssdp-amplification",
            f"SSDP/UPnP responde a M-SEARCH en {svc.host}:{svc.port} — vector de amplificación DDoS.",
            f"M-SEARCH devolvió {len(resp)} bytes (factor de amplificación)",
            "Bloquear UDP/1900 desde internet; deshabilitar UPnP en el perímetro.",
        )
    return None


def _check_chargen(svc: DiscoveredService) -> Finding | None:
    resp = _udp(svc.host, svc.port, b"\x01", 1024)
    if resp and len(resp) > 50:
        return _f(
            svc, "CWE-406", "MEDIUM", "chargen-amplification",
            f"Servicio CharGen activo en {svc.host}:{svc.port} — amplificación DDoS clásica.",
            f"Un byte UDP devolvió {len(resp)} bytes de caracteres",
            "Deshabilitar chargen/echo/qotd (inetd) — son servicios legacy sin uso legítimo.",
        )
    return None


# ---------------------------------------------------------------------------
# TLS/SSL hygiene (read-only handshake): cert validity + weak protocol/cipher
# ---------------------------------------------------------------------------


def _tls_accepts(host: str, port: int, version) -> bool:
    import ssl  # noqa: PLC0415

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # modern OpenSSL won't even offer legacy otherwise
    except (ValueError, OSError):
        return False
    try:
        with socket.create_connection((host, port), timeout=_T) as s, ctx.wrap_socket(s, server_hostname=host):
            return True
    except (OSError, ValueError):
        return False


def _check_tls(svc: DiscoveredService) -> list[Finding]:
    """Expired/self-signed/soon-to-expire cert, legacy TLS 1.0/1.1 accepted, weak
    negotiated cipher. Read-only TLS handshake; cert parse via cryptography (soft)."""
    import ssl  # noqa: PLC0415

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((svc.host, svc.port), timeout=_T) as s, ctx.wrap_socket(
            s, server_hostname=svc.host
        ) as ss:
            der = ss.getpeercert(binary_form=True)
            cipher = (ss.cipher() or ("", "", 0))[0]
    except (OSError, ValueError):
        return []  # not TLS / unreachable

    out: list[Finding] = []
    if der:
        try:
            from datetime import datetime, timezone  # noqa: PLC0415

            from cryptography import x509  # noqa: PLC0415

            cert = x509.load_der_x509_certificate(der)
            try:
                na, now = cert.not_valid_after_utc, datetime.now(timezone.utc)
            except AttributeError:
                na, now = cert.not_valid_after, datetime.utcnow()  # noqa: DTZ003
            days = (na - now).days
            if days < 0:
                out.append(_f(svc, "CWE-298", "HIGH", "tls-cert-expired",
                    f"Certificado TLS EXPIRADO en {svc.host}:{svc.port} (venció hace {-days} días).",
                    f"notAfter={na.isoformat()}", "Renovar el certificado; automatizar con ACME/Let's Encrypt."))
            elif days < 30:
                out.append(_f(svc, "CWE-298", "LOW", "tls-cert-expiring",
                    f"Certificado TLS vence en {days} días en {svc.host}:{svc.port}.",
                    f"notAfter={na.isoformat()}", "Renovar antes del vencimiento; automatizar la rotación."))
            if cert.issuer == cert.subject:
                out.append(_f(svc, "CWE-295", "MEDIUM", "tls-cert-self-signed",
                    f"Certificado TLS self-signed en {svc.host}:{svc.port}.",
                    f"issuer == subject ({cert.subject.rfc4514_string()[:60]})",
                    "Usar un cert emitido por una CA confiable; self-signed habilita MITM."))
        except Exception:  # noqa: BLE001 — cert parse best-effort
            pass

    if cipher and any(w in cipher.upper() for w in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "-MD5")):
        out.append(_f(svc, "CWE-327", "MEDIUM", "tls-weak-cipher",
            f"Cipher TLS débil negociado en {svc.host}:{svc.port}: {cipher}.",
            f"El server prefiere {cipher}",
            "Deshabilitar RC4/3DES/DES/NULL/EXPORT; usar AEAD (AES-GCM/ChaCha20)."))

    for ver, label in ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1")):
        if _tls_accepts(svc.host, svc.port, ver):
            out.append(_f(svc, "CWE-327", "MEDIUM", "tls-legacy-protocol",
                f"{label} aceptado en {svc.host}:{svc.port} (protocolo obsoleto/inseguro).",
                f"Handshake forzado con {label} tuvo éxito",
                f"Deshabilitar {label} y SSLv3; exigir TLS 1.2+ (idealmente 1.3)."))
    return out


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
    # Batch A — data stores
    ("memcached", lambda s: s.service == "memcache" or s.port == 11211, _check_memcached),
    ("zookeeper", lambda s: s.service == "zookeeper" or s.port == 2181, _check_zookeeper),
    ("couchdb", lambda s: s.port == 5984, _check_couchdb),
    ("etcd", lambda s: s.port in (2379, 2380), _check_etcd),
    ("consul", lambda s: s.port == 8500, _check_consul),
    ("solr", lambda s: s.port == 8983, _check_solr),
    ("influxdb", lambda s: s.port == 8086, _check_influxdb),
    ("clickhouse", lambda s: s.port == 8123, _check_clickhouse),
    ("rabbitmq", lambda s: s.port == 15672, _check_rabbitmq_mgmt),
    # Batch A — container / orchestration
    ("docker", lambda s: s.port in (2375, 2376), _check_docker_api),
    ("kubelet", lambda s: s.port == 10250, _check_kubelet),
    ("k8s-api", lambda s: s.port in (6443, 8443), _check_k8s_api),
    # Batch A — amplification
    ("ssdp", lambda s: s.port == 1900, _check_ssdp),
    ("chargen", lambda s: s.port == 19, _check_chargen),
    # Batch C — TLS hygiene (returns a list)
    ("tls", lambda s: s.service in ("https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps")
        or s.port in (443, 8443, 993, 995, 465, 636, 990, 5061, 9443), _check_tls),
)


def run_service_probes(svc: DiscoveredService) -> list[Finding]:
    """Run every matching probe against a discovered service. Never raises."""
    out: list[Finding] = []
    for _name, matches, probe in PROBES:
        try:
            if matches(svc):
                f = probe(svc)
                if isinstance(f, list):  # some probes (TLS) emit multiple findings
                    out.extend(f)
                elif f:
                    out.append(f)
        except Exception:  # noqa: BLE001 — a probe must never break the sweep
            continue
    return out
