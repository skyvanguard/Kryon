"""Tests for admin API endpoints."""

import sqlite3

import pytest
from starlette.testclient import TestClient

from kryon.memory.store import MemoryStore
from kryon.server import ServerConfig, create_app
from kryon.server.auth.models import User
from kryon.server.auth.password import hash_password


class _SafeStore(MemoryStore):
    def _get_conn(self):
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), timeout=30, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
        return self._conn


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    """TestClient with admin endpoints accessible (no auth)."""
    store = _SafeStore(db_path=tmp_path / "admin_test.db")

    import kryon.server.routes.clients as clients_mod
    monkeypatch.setattr(clients_mod, "_store", store)

    app = create_app(ServerConfig(api_keys=[]))
    with TestClient(app) as c:
        yield c, store
    store.close()


def test_admin_health(admin_client):
    client, store = admin_client
    resp = client.get("/api/v1/admin/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "schema_version" in data
    assert "user_count" in data
    assert "db_size_bytes" in data
    assert "tables" in data


def test_admin_backup(admin_client):
    client, store = admin_client
    resp = client.post("/api/v1/admin/backup")
    assert resp.status_code == 200
    data = resp.json()
    assert "path" in data
    assert "timestamp" in data


def test_admin_user_crud(admin_client):
    client, store = admin_client

    # Create user
    resp = client.post("/api/v1/admin/users", json={
        "username": "newuser",
        "email": "new@test.com",
        "password": "secret1234",
        "role": "analyst",
    })
    assert resp.status_code == 200
    user_data = resp.json()
    assert user_data["username"] == "newuser"
    assert "password_hash" not in user_data
    user_id = user_data["id"]

    # List users
    resp = client.get("/api/v1/admin/users")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # Update user
    resp = client.put(f"/api/v1/admin/users/{user_id}", json={
        "role": "viewer",
    })
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"

    # Delete user
    resp = client.delete(f"/api/v1/admin/users/{user_id}")
    assert resp.status_code == 200

    # Verify deleted
    resp = client.get("/api/v1/admin/users")
    assert len(resp.json()) == 0


def test_admin_create_duplicate_username(admin_client):
    client, _ = admin_client
    client.post("/api/v1/admin/users", json={
        "username": "dup",
        "email": "dup@test.com",
        "password": "secret1234",
    })
    resp = client.post("/api/v1/admin/users", json={
        "username": "dup",
        "email": "dup2@test.com",
        "password": "secret1234",
    })
    assert resp.status_code == 400
