"""Batch K/N — deterministic detectors for infrastructure services that ship
without auth by default and are rarely locked down: Docker Registry v2 (image/
secret leak), anonymous MQTT brokers (IoT/OT), NATS, Java RMI registry
(deserialization RCE surface), open git daemon (anonymous clone), no-auth
Cassandra, exposed Neo4j, JDWP (unauth RCE), and Cisco Smart Install
(CVE-2018-0171). Each is CONFIRMED by a protocol response.

READ-ONLY, graceful. Imports utilities from service_probes (one-way; engage
imports the probe modules lazily, so no import cycle). Complements the existing
DB-exposure (no-TLS, CWE-319) check in engage — these surface auth bypass /
RCE / data-leak (CWE-306/502), a different and higher-value class of finding.
"""

from __future__ import annotations

import struct

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _http_get, _tcp, run_table


def _check_docker_registry(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """Docker Registry v2 with anonymous catalog access = every image (and the
    secrets/source baked into them) is pullable."""
    cat = _http_get(svc.host, svc.port, "/v2/_catalog", scheme=scheme)
    if cat and cat[0] == 200 and '"repositories"' in cat[1]:
        return _f(
            svc, "CWE-306", "HIGH", "docker-registry-open",
            f"Docker Registry v2 con catálogo anónimo en {svc.host}:{svc.port} — todas las imágenes son descargables.",
            "GET /v2/_catalog → 200 con la lista de repositorios (código/secrets horneados en las imágenes)",
            "Habilitar auth (htpasswd/token) en el registry; restringir a la red de CI/CD; usar pull-secrets.",
        )
    return None


def _check_mqtt(svc: DiscoveredService) -> Finding | None:
    """MQTT broker accepting anonymous CONNECT (CONNACK return code 0x00)."""
    var = b"\x00\x04MQTT\x04\x02\x00\x3c"  # protocol name + level 3.1.1 + clean-session + keepalive
    payload = b"\x00\x05kryon"  # client id
    body = var + payload
    pkt = b"\x10" + bytes([len(body)]) + body
    resp = _tcp(svc.host, svc.port, pkt, 16)
    if resp and len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
        return _f(
            svc, "CWE-306", "HIGH", "mqtt-anonymous",
            f"Broker MQTT acepta conexiones anónimas en {svc.host}:{svc.port} — pub/sub sin autenticación (IoT/OT).",
            "CONNECT sin credenciales → CONNACK return-code 0x00 (Connection Accepted)",
            "Exigir autenticación (allow_anonymous false) + ACLs por tópico; TLS (8883); aislar la red OT.",
        )
    return None


def _check_nats(svc: DiscoveredService) -> Finding | None:
    """NATS server advertising auth_required=false → anonymous pub/sub to all subjects."""
    resp = _tcp(svc.host, svc.port, b"", 1024)  # NATS sends INFO {...} on connect
    if resp and resp.startswith(b"INFO "):
        text = resp.decode("latin-1", "replace")
        if '"auth_required":true' not in text.replace(" ", ""):
            return _f(
                svc, "CWE-306", "HIGH", "nats-no-auth",
                f"Servidor NATS sin autenticación en {svc.host}:{svc.port} — pub/sub anónimo a todos los subjects.",
                "Banner INFO sin auth_required=true (conexión anónima permitida)",
                "Configurar authorization (token/user-pass/nkeys) + TLS; restringir a la red de servicios.",
            )
    return None


def _check_rmi(svc: DiscoveredService) -> Finding | None:
    """Java RMI registry: JRMI handshake → ProtocolAck ('N'). Exposed RMI is a
    classic Java deserialization RCE surface (ysoserial / JRMP)."""
    resp = _tcp(svc.host, svc.port, b"JRMI\x00\x02\x4b", 32)
    if resp and resp[:1] == b"\x4e":  # 0x4e 'N' = ProtocolAck
        return _f(
            svc, "CWE-502", "HIGH", "rmi-registry-exposed",
            f"Java RMI registry expuesto en {svc.host}:{svc.port} — superficie de deserialización (RCE vía JRMP/ysoserial).",
            "Handshake JRMI → ProtocolAck (0x4e) = registro RMI alcanzable",
            "No exponer RMI a redes no confiables; filtrar deserialización (JEP 290/ObjectInputFilter); usar TLS+auth.",
        )
    return None


def _check_git_daemon(svc: DiscoveredService) -> Finding | None:
    """git daemon (9418) serving an anonymous repo (git-upload-pack ref advertisement)."""
    req = "git-upload-pack /\x00host=kryon\x00"
    line = (f"{len(req) + 4:04x}" + req).encode("latin-1")
    resp = _tcp(svc.host, svc.port, line, 256)
    if not resp:
        return None
    text = resp.decode("latin-1", "replace")
    if "ERR " in text[:80]:  # access denied / repo not found → not anonymously cloneable
        return None
    if "refs/" in text or "HEAD" in text or "git-upload-pack" in text:
        return _f(
            svc, "CWE-306", "MEDIUM", "git-daemon-anonymous",
            f"git daemon en {svc.host}:{svc.port} permite clonado anónimo — fuga de código fuente/historial.",
            "git-upload-pack → ref advertisement (sin auth)",
            "Deshabilitar el git daemon o el acceso anónimo; servir el repo vía SSH/HTTPS autenticado.",
        )
    return None


def _cql_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return len(b).to_bytes(2, "big") + b


def _cql_frame(opcode: int, body: bytes = b"") -> bytes:
    # version 0x04 (request), flags 0, stream 0x0000, opcode, length(4)
    return b"\x04\x00\x00\x00" + bytes([opcode]) + len(body).to_bytes(4, "big") + body


def _check_cassandra(svc: DiscoveredService) -> Finding | None:
    """Cassandra/Scylla CQL native protocol. OPTIONS → a CQL response confirms it;
    STARTUP returning READY (not AUTHENTICATE) means authentication is disabled."""
    opt = _tcp(svc.host, svc.port, _cql_frame(0x05), 512)  # OPTIONS
    if not (opt and len(opt) >= 9 and (opt[0] & 0x80)):  # response frame (version high bit set)
        return None
    startup = _cql_frame(0x01, (1).to_bytes(2, "big") + _cql_string("CQL_VERSION") + _cql_string("3.0.0"))
    resp = _tcp(svc.host, svc.port, startup, 512)
    if resp and len(resp) >= 9 and (resp[0] & 0x80) and resp[4] == 0x02:  # READY
        return _f(
            svc, "CWE-306", "HIGH", "cassandra-no-auth",
            f"Cassandra/Scylla sin autenticación en {svc.host}:{svc.port} — acceso total a los keyspaces.",
            "STARTUP → READY (el server no exige AUTHENTICATE)",
            "Activar PasswordAuthenticator + CassandraAuthorizer; TLS client_encryption; restringir bind.",
        )
    return None


def _check_jdwp(svc: DiscoveredService) -> Finding | None:
    """Java Debug Wire Protocol exposed: the server echoes the 'JDWP-Handshake'
    string → trivial unauthenticated RCE (arbitrary bytecode via the debugger)."""
    resp = _tcp(svc.host, svc.port, b"JDWP-Handshake", 32)
    if resp and resp[:14] == b"JDWP-Handshake":
        return _f(
            svc, "CWE-306", "CRITICAL", "jdwp-exposed",
            f"JDWP (debug de la JVM) expuesto en {svc.host}:{svc.port} — RCE trivial sin autenticación.",
            "El server ecoó 'JDWP-Handshake' (el debugger permite ejecutar bytecode arbitrario)",
            "Nunca correr la JVM con -agentlib:jdwp/-Xdebug en producción; no exponer el puerto de debug.",
        )
    return None


def _check_smart_install(svc: DiscoveredService) -> Finding | None:
    """Cisco Smart Install (4786) active: responds to the SMI probe with the SMI
    header → CVE-2018-0171 surface (unauth config exfil / TFTP trigger / RCE)."""
    probe = bytes.fromhex("00000001000000010000000000000004000000080000000100000000")
    resp = _tcp(svc.host, svc.port, probe, 64)
    if resp and resp[:4] == b"\x00\x00\x00\x01":  # SMI version header echoed
        return _f(
            svc, "CWE-306", "HIGH", "cisco-smart-install",
            f"Cisco Smart Install activo en {svc.host}:{svc.port} — CVE-2018-0171 (exfil de config / RCE sin auth).",
            "Respuesta con header SMI (version 0x00000001) al probe de Smart Install",
            "Deshabilitar Smart Install ('no vstack'); filtrar TCP/4786; aplicar el advisory de Cisco.",
        )
    return None


def _check_neo4j(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """Neo4j HTTP API exposed; unauthenticated query endpoint = full graph access."""
    root = _http_get(svc.host, svc.port, "/", scheme=scheme)
    is_neo4j = root and root[0] in (200, 401) and ("neo4j_version" in root[1] or "neo4j" in root[1].lower() or "bolt" in root[1].lower())
    if not is_neo4j:
        return None
    # Unauthenticated data/transaction endpoint reachable? 200 = no auth; 401 = auth on.
    for path in ("/db/data/", "/db/neo4j/tx/commit", "/db/system/tx/commit"):
        d = _http_get(svc.host, svc.port, path, scheme=scheme)
        if d and d[0] == 200:
            return _f(
                svc, "CWE-306", "HIGH", "neo4j-no-auth",
                f"Neo4j sin autenticación en {svc.host}:{svc.port} — acceso completo a la base de grafos.",
                f"GET {path} → 200 sin credenciales",
                "Activar dbms.security.auth_enabled=true; cambiar la default neo4j:neo4j; restringir 7474/7687.",
            )
    return _f(
        svc, "CWE-1392", "LOW", "neo4j-exposed",
        f"Neo4j expuesto en {svc.host}:{svc.port} — verificar credenciales por defecto (neo4j:neo4j).",
        "HTTP API de Neo4j alcanzable",
        "Cambiar la contraseña por defecto; restringir el acceso de red a 7474/7687.",
    )


# --------------------------------------------------------------------------
# Batch S — additional data stores / brokers / secret-mgmt
# --------------------------------------------------------------------------


def _check_epmd(svc: DiscoveredService) -> Finding | None:
    """Erlang Port Mapper Daemon: NAMES_REQ enumerates the cluster's nodes (and
    their distribution ports — the real attack surface via the Erlang cookie)."""
    resp = _tcp(svc.host, svc.port, b"\x00\x01\x6e", 1024)  # len=1, 'n' = NAMES_REQ
    if resp and len(resp) >= 4 and b" at port " in resp:
        nodes = resp[4:].decode("latin-1", "replace").replace("\n", " ").strip()
        return _f(svc, "CWE-200", "HIGH", "epmd-exposed",
                  f"Erlang EPMD expuesto en {svc.host}:{svc.port} — enumera nodos del cluster (RabbitMQ/CouchDB/Ejabberd).",
                  f"NAMES_REQ → {nodes[:120]}",
                  "Filtrar 4369 + el rango de puertos de distribución; proteger el ~/.erlang.cookie; bind a red interna.")
    return None


def _check_oracle_tns(svc: DiscoveredService) -> Finding | None:
    """Oracle TNS listener: a connect packet elicits a TNS-framed reply; an
    unrestricted (COMMAND=version) leaks the version → CVE matching."""
    data = b"(CONNECT_DATA=(COMMAND=version))"
    hdr = (b"\x00\x00\x00\x00\x01\x00\x00\x00"
           b"\x01\x36\x01\x2c\x00\x00\x08\x00\x7f\xff\x4f\x98\x00\x00\x00\x01"
           + struct.pack(">H", len(data)) + b"\x00\x34\x00\x00\x00\x00\x01\x01"
           + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    pkt = struct.pack(">H", len(hdr) + len(data)) + hdr[2:] + data
    resp = _tcp(svc.host, svc.port, pkt, 1024)
    if resp and len(resp) >= 5 and resp[4] in (0x02, 0x04, 0x06, 0x0b, 0x0c):  # TNS accept/refuse/data/resend/marker
        ver = ""
        for marker in (b"VSNNUM", b"Version", b"TNSLSNR"):
            if marker in resp:
                ver = resp[resp.index(marker):resp.index(marker) + 60].decode("latin-1", "replace")
                break
        return _f(svc, "CWE-200", "HIGH", "oracle-tns-exposed",
                  f"Oracle TNS listener expuesto en {svc.host}:{svc.port} — info-leak / version disclosure.",
                  f"Respuesta TNS{(' · ' + ver) if ver else ''}",
                  "Restringir el listener (VALID_NODE_CHECKING + ACL); ADMIN_RESTRICTIONS=ON; no exponer 1521.")
    return None


def _check_cockroach(svc: DiscoveredService) -> Finding | None:
    """CockroachDB (Postgres wire) in --insecure mode answers AuthenticationOk
    to a startup with no password."""
    msg = b"user\x00root\x00database\x00defaultdb\x00\x00"
    startup = struct.pack(">I", 8 + len(msg)) + struct.pack(">I", 196608) + msg
    resp = _tcp(svc.host, svc.port, startup, 64)
    if resp and resp[:1] == b"R" and len(resp) >= 9 and int.from_bytes(resp[5:9], "big") == 0:  # AuthenticationOk
        return _f(svc, "CWE-1392", "HIGH", "cockroachdb-insecure",
                  f"CockroachDB en modo --insecure en {svc.host}:{svc.port} — sin TLS ni autenticación.",
                  "StartupMessage(user=root) → AuthenticationOk (sin password)",
                  "Arrancar con --certs-dir (modo seguro); exigir TLS + auth; nunca exponer 26257 sin cifrado.")
    return None


def _check_redis_sentinel(svc: DiscoveredService) -> Finding | None:
    """Redis Sentinel without auth leaks the HA topology (master IPs/ports)."""
    resp = _tcp(svc.host, svc.port, b"INFO sentinel\r\n", 512)
    if resp and b"sentinel_masters:" in resp and b"NOAUTH" not in resp:
        return _f(svc, "CWE-200", "MEDIUM", "redis-sentinel-exposed",
                  f"Redis Sentinel sin auth en {svc.host}:{svc.port} — expone la topología HA (masters reales).",
                  "INFO sentinel → sentinel_masters sin requerir AUTH",
                  "Setear requirepass en Sentinel (Redis 5+); bind a la red interna; no exponer 26379.")
    return None


def _check_amqp(svc: DiscoveredService) -> Finding | None:
    """Raw AMQP 0-9-1 broker (the one a 15672 mgmt-UI check can't see)."""
    resp = _tcp(svc.host, svc.port, b"AMQP\x00\x00\x09\x01", 512)
    if resp and (resp[:1] == b"\x01" or resp[:4] == b"AMQP"):  # Connection.Start frame or proto-header reply
        return _f(svc, "CWE-1392", "MEDIUM", "amqp-broker-exposed",
                  f"Broker AMQP expuesto en {svc.host}:{svc.port} — verificar credenciales por defecto (guest/guest).",
                  "Header AMQP 0-9-1 → respuesta del broker (Connection.Start)",
                  "Deshabilitar el usuario guest o restringirlo a localhost; TLS (5671); auth fuerte por vhost.")
    return None


def _check_minio(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """Anonymous S3-compatible object store (MinIO et al.): ListBuckets without
    a signature = every bucket/object is enumerable."""
    r = _http_get(svc.host, svc.port, "/", scheme=scheme)
    if r and r[0] == 200 and "<ListAllMyBucketsResult" in r[1]:
        return _f(svc, "CWE-284", "HIGH", "object-store-public-buckets",
                  f"Object store S3-compatible con ListBuckets anónimo en {svc.host}:{svc.port} — datos enumerables.",
                  "GET / → <ListAllMyBucketsResult> sin firma AWS (acceso anónimo)",
                  "Exigir autenticación/políticas de bucket; nunca dejar el acceso anónimo en el object store.")
    return None


def _check_vault(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """HashiCorp Vault /sys/health: unsealed over plaintext = secrets at risk."""
    r = _http_get(svc.host, svc.port, "/v1/sys/health", scheme=scheme)
    if not (r and "sealed" in r[1] and ("version" in r[1] or "cluster_name" in r[1])):
        return None
    body = r[1].replace(" ", "")
    if '"sealed":false' in body:
        sev = "CRITICAL" if scheme == "http" else "HIGH"
        return _f(svc, "CWE-306", sev, "vault-unsealed",
                  f"HashiCorp Vault UNSEALED y alcanzable en {svc.host}:{svc.port}{' (sin TLS)' if scheme == 'http' else ''}.",
                  "GET /v1/sys/health → sealed:false (los secretos están desencriptados en memoria)",
                  "Sellar Vault salvo durante operación; exigir TLS; restringir 8200 a la red de aplicaciones.")
    return _f(svc, "CWE-200", "LOW", "vault-exposed",
              f"HashiCorp Vault alcanzable en {svc.host}:{svc.port} (sealed).",
              "GET /v1/sys/health respondió (Vault expuesto a la red)",
              "Restringir 8200 a la red interna; TLS obligatorio.")


def _check_portainer(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """Portainer with no admin initialized = anyone can claim admin of the Docker host."""
    status = _http_get(svc.host, svc.port, "/api/system/status", scheme=scheme)
    is_portainer = status and status[0] == 200 and ("Version" in status[1] or "Edition" in status[1])
    if not is_portainer:
        return None
    chk = _http_get(svc.host, svc.port, "/api/users/admin/check", scheme=scheme)
    if chk and chk[0] == 404:
        return _f(svc, "CWE-862", "CRITICAL", "portainer-uninitialized",
                  f"Portainer SIN admin inicializado en {svc.host}:{svc.port} — cualquiera puede reclamar el admin del daemon Docker.",
                  "GET /api/users/admin/check → 404 (POST /api/users/admin/init toma control total)",
                  "Inicializar el admin de inmediato detrás de la red de management; nunca exponer Portainer sin setup.")
    return _f(svc, "CWE-1392", "LOW", "portainer-exposed",
              f"Portainer expuesto en {svc.host}:{svc.port} — verificar credenciales y acceso de red.",
              "GET /api/system/status → 200 (Portainer alcanzable)",
              "Restringir Portainer a la red de management/VPN; MFA; credenciales fuertes.")


def _check_arango(svc: DiscoveredService, scheme: str = "http") -> Finding | None:
    """ArangoDB with authentication disabled (--server.authentication false)."""
    r = _http_get(svc.host, svc.port, "/_api/version", scheme=scheme)
    if r and r[0] == 200 and "arango" in r[1].lower() and "version" in r[1].lower():
        return _f(svc, "CWE-306", "HIGH", "arangodb-no-auth",
                  f"ArangoDB con autenticación deshabilitada en {svc.host}:{svc.port} — acceso total a la base.",
                  "GET /_api/version → 200 sin 401 (auth off)",
                  "Activar server.authentication=true; cambiar la contraseña de root; restringir 8529.")
    return None


# (name, port matcher, detector). HTTP detectors take (svc, scheme); the rest take (svc).
_HTTP_PROBES = (
    ("docker-registry", lambda s: s.port in (5000, 5001), _check_docker_registry),
    ("neo4j", lambda s: s.port == 7474, _check_neo4j),
    ("minio", lambda s: s.port in (9000, 9001), _check_minio),
    ("vault", lambda s: s.port == 8200, _check_vault),
    ("portainer", lambda s: s.port in (9000, 9443), _check_portainer),
    ("arango", lambda s: s.port == 8529, _check_arango),
)
_TCP_PROBES = (
    ("mqtt", lambda s: s.port in (1883, 8883), _check_mqtt),
    ("nats", lambda s: s.port == 4222, _check_nats),
    ("rmi", lambda s: s.port in (1099, 1098, 11099), _check_rmi),
    ("git-daemon", lambda s: s.port == 9418, _check_git_daemon),
    ("cassandra", lambda s: s.port in (9042, 9142), _check_cassandra),
    ("jdwp", lambda s: s.port in (8000, 5005, 8787, 9999, 18000), _check_jdwp),
    ("smart-install", lambda s: s.port == 4786, _check_smart_install),
    ("epmd", lambda s: s.port == 4369, _check_epmd),
    ("oracle-tns", lambda s: s.port in (1521, 1522, 1523, 1524, 1525, 1526), _check_oracle_tns),
    ("cockroachdb", lambda s: s.port == 26257, _check_cockroach),
    ("redis-sentinel", lambda s: s.port == 26379, _check_redis_sentinel),
    ("amqp", lambda s: s.port in (5672, 5671), _check_amqp),
)


def run_infra_probes(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Run matching infrastructure-service probes. Never raises."""
    return run_table(svc, _HTTP_PROBES, scheme) + run_table(svc, _TCP_PROBES)
