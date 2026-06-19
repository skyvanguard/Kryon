"""Batch K — infra-service probes (Docker Registry, MQTT, NATS, Java RMI,
git daemon, Cassandra, Neo4j). Protocol responses mocked; graceful-on-unreachable
and signature precision checked directly.
"""

from __future__ import annotations

import kryon.cli.infra_probes as ip
from kryon.cli.engage import DiscoveredService
from kryon.cli.infra_probes import _HTTP_PROBES, _TCP_PROBES, run_infra_probes

_DEAD = "127.0.0.1"


def _svc(port: int) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="")


def test_run_infra_probes_graceful_on_dead_ports():
    for port in (5000, 7474, 1883, 4222, 1099, 9418, 9042):
        assert isinstance(run_infra_probes(_svc(port)), list)


def test_dispatch_tables_well_formed():
    assert len(_HTTP_PROBES) == 2 and len(_TCP_PROBES) == 7
    for _n, m, p in (*_HTTP_PROBES, *_TCP_PROBES):
        assert callable(m) and callable(p)


def test_docker_registry_open(monkeypatch):
    monkeypatch.setattr(ip, "_http_get", lambda *a, **k: (200, '{"repositories":["app","db"]}'))
    f = ip._check_docker_registry(_svc(5000))
    assert f is not None and f.rule_id == "docker-registry-open" and f.severity == "HIGH"


def test_docker_registry_authed_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_http_get", lambda *a, **k: (401, "unauthorized"))
    assert ip._check_docker_registry(_svc(5000)) is None


def test_mqtt_anonymous_accepted(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"\x20\x02\x00\x00")  # CONNACK rc=0x00
    assert ip._check_mqtt(_svc(1883)).rule_id == "mqtt-anonymous"


def test_mqtt_refused_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"\x20\x02\x00\x05")  # rc=0x05 not authorized
    assert ip._check_mqtt(_svc(1883)) is None


def test_nats_no_auth(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b'INFO {"server_id":"x","auth_required":false}\r\n')
    assert ip._check_nats(_svc(4222)).rule_id == "nats-no-auth"


def test_nats_auth_required_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b'INFO {"server_id":"x","auth_required":true}\r\n')
    assert ip._check_nats(_svc(4222)) is None


def test_rmi_registry_exposed(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"\x4e\x00\x09localhost\x00\x00\x00\x00")  # ProtocolAck
    f = ip._check_rmi(_svc(1099))
    assert f is not None and f.rule_id == "rmi-registry-exposed" and f.cwe == "CWE-502"


def test_rmi_no_ack_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"\x00garbage")
    assert ip._check_rmi(_svc(1099)) is None


def test_git_daemon_anonymous(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"00ab2cb58b79488a98d2721cea644875a8dd0026b115 HEAD\x00refs/heads/main\n")
    assert ip._check_git_daemon(_svc(9418)).rule_id == "git-daemon-anonymous"


def test_git_daemon_access_denied_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"0048ERR access denied or repository not exported\n")
    assert ip._check_git_daemon(_svc(9418)) is None


def test_cassandra_no_auth(monkeypatch):
    # OPTIONS → response (0x84 = response v4); STARTUP → READY (opcode 0x02 at offset 4).
    opt = b"\x84\x00\x00\x00\x06\x00\x00\x00\x00"
    ready = b"\x84\x00\x00\x00\x02\x00\x00\x00\x00"
    calls = iter([opt, ready])
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: next(calls))
    assert ip._check_cassandra(_svc(9042)).rule_id == "cassandra-no-auth"


def test_cassandra_auth_required_returns_none(monkeypatch):
    opt = b"\x84\x00\x00\x00\x06\x00\x00\x00\x00"
    authenticate = b"\x84\x00\x00\x00\x03\x00\x00\x00\x00"  # AUTHENTICATE
    calls = iter([opt, authenticate])
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: next(calls))
    assert ip._check_cassandra(_svc(9042)) is None


def test_neo4j_no_auth(monkeypatch):
    def fake(host, port, path, scheme="http", **k):
        if path == "/":
            return (200, '{"neo4j_version":"5.1.0","bolt_routing":"x"}')
        return (200, '{"results":[]}')
    monkeypatch.setattr(ip, "_http_get", fake)
    assert ip._check_neo4j(_svc(7474)).rule_id == "neo4j-no-auth"


def test_neo4j_authed_is_low(monkeypatch):
    def fake(host, port, path, scheme="http", **k):
        if path == "/":
            return (401, '{"neo4j_version":"5.1.0"}')
        return (401, "unauthorized")
    monkeypatch.setattr(ip, "_http_get", fake)
    f = ip._check_neo4j(_svc(7474))
    assert f is not None and f.rule_id == "neo4j-exposed" and f.severity == "LOW"


def test_neo4j_absent_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_http_get", lambda *a, **k: (200, "<html>nginx</html>"))
    assert ip._check_neo4j(_svc(7474)) is None


# ---------------------------------------------------------------------------
# Batch N — JDWP (unauth RCE) + Cisco Smart Install (CVE-2018-0171)
# ---------------------------------------------------------------------------


def test_jdwp_exposed_is_critical(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"JDWP-Handshake")
    f = ip._check_jdwp(_svc(8000))
    assert f is not None and f.rule_id == "jdwp-exposed" and f.severity == "CRITICAL"


def test_jdwp_http_server_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"HTTP/1.1 400 Bad Request\r\n")
    assert ip._check_jdwp(_svc(8000)) is None
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: None)
    assert ip._check_jdwp(_svc(8000)) is None


def test_smart_install_detected(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"\x00\x00\x00\x01\x00\x00\x00\x03" + b"\x00" * 8)
    f = ip._check_smart_install(_svc(4786))
    assert f is not None and f.rule_id == "cisco-smart-install" and f.severity == "HIGH"


def test_smart_install_absent_returns_none(monkeypatch):
    monkeypatch.setattr(ip, "_tcp", lambda *a, **k: b"\xde\xad\xbe\xef")
    assert ip._check_smart_install(_svc(4786)) is None
