"""Batch K — deterministic detectors for infrastructure services that ship
without auth by default and are rarely locked down: Docker Registry v2 (image/
secret leak), anonymous MQTT brokers (IoT/OT), NATS, Java RMI registry
(deserialization RCE surface), open git daemon (anonymous clone), no-auth
Cassandra, and exposed Neo4j. Each is CONFIRMED by a protocol response.

READ-ONLY, graceful. Imports utilities from service_probes (one-way; engage
imports the probe modules lazily, so no import cycle). Complements the existing
DB-exposure (no-TLS, CWE-319) check in engage — these surface auth bypass /
RCE / data-leak (CWE-306/502), a different and higher-value class of finding.
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _http_get, _tcp


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


# (name, port matcher, detector). HTTP detectors take (svc, scheme); the rest take (svc).
_HTTP_PROBES = (
    ("docker-registry", lambda s: s.port in (5000, 5001), _check_docker_registry),
    ("neo4j", lambda s: s.port == 7474, _check_neo4j),
)
_TCP_PROBES = (
    ("mqtt", lambda s: s.port in (1883, 8883), _check_mqtt),
    ("nats", lambda s: s.port == 4222, _check_nats),
    ("rmi", lambda s: s.port in (1099, 1098, 11099), _check_rmi),
    ("git-daemon", lambda s: s.port == 9418, _check_git_daemon),
    ("cassandra", lambda s: s.port in (9042, 9142), _check_cassandra),
)


def run_infra_probes(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Run matching infrastructure-service probes. Never raises."""
    out: list[Finding] = []
    for _name, matches, probe in _HTTP_PROBES:
        try:
            if matches(svc):
                f = probe(svc, scheme)
                if f:
                    out.append(f)
        except Exception:  # noqa: BLE001
            continue
    for _name, matches, probe in _TCP_PROBES:
        try:
            if matches(svc):
                f = probe(svc)
                if f:
                    out.append(f)
        except Exception:  # noqa: BLE001
            continue
    return out
