"""Tests for audit logging system."""

import sqlite3

import pytest

from kryon.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path):
    s = MemoryStore(db_path=tmp_path / "audit.db")
    yield s
    s.close()


def test_write_and_read_audit_log(store):
    entry = {
        "id": "aud-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "user_id": "u1",
        "username": "admin",
        "action": "POST /api/clients",
        "resource_type": "clients",
        "resource_id": "c1",
        "details": {"status_code": 200},
        "ip_address": "127.0.0.1",
        "request_id": "abc12345",
    }
    store.write_audit_log(entry)

    logs = store.get_audit_logs(limit=10)
    assert len(logs) == 1
    assert logs[0]["action"] == "POST /api/clients"
    assert logs[0]["username"] == "admin"


def test_audit_log_filters(store):
    for i in range(3):
        store.write_audit_log({
            "id": f"aud-{i}",
            "timestamp": f"2026-01-0{i + 1}T00:00:00Z",
            "user_id": "u1" if i < 2 else "u2",
            "username": "admin" if i < 2 else "analyst",
            "action": f"action-{i}",
            "resource_type": "clients" if i == 0 else "scans",
            "resource_id": None,
            "details": {},
            "ip_address": "127.0.0.1",
            "request_id": f"r{i}",
        })

    logs = store.get_audit_logs(user_id="u1")
    assert len(logs) == 2

    logs = store.get_audit_logs(resource_type="clients")
    assert len(logs) == 1

    logs = store.get_audit_logs(action="action-0")
    assert len(logs) == 1


def test_audit_log_limit(store):
    for i in range(5):
        store.write_audit_log({
            "id": f"aud-{i}",
            "timestamp": f"2026-01-0{i + 1}T00:00:00Z",
            "action": f"action-{i}",
            "resource_type": "clients",
            "details": {},
        })

    logs = store.get_audit_logs(limit=3)
    assert len(logs) == 3


def test_audit_endpoint_accessible(tmp_path, monkeypatch):
    """Audit endpoint should be accessible (no JWT = admin by default)."""
    import sqlite3

    from kryon.server import ServerConfig, create_app

    class _SafeStore(MemoryStore):
        def _get_conn(self):
            if self._conn is None:
                self._conn = sqlite3.connect(str(self._db_path), timeout=30, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._conn.execute("PRAGMA busy_timeout=5000")
            return self._conn

    s = _SafeStore(db_path=tmp_path / "audit_ep.db")
    import kryon.server.routes.clients as clients_mod
    monkeypatch.setattr(clients_mod, "_store", s)

    from starlette.testclient import TestClient

    app = create_app(ServerConfig(api_keys=[]))
    with TestClient(app) as c:
        resp = c.get("/api/v1/audit")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    s.close()
