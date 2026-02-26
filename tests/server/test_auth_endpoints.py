"""Tests for authentication API endpoints."""

import sqlite3

import pytest
from starlette.testclient import TestClient

from kryon.memory.store import MemoryStore
from kryon.server import ServerConfig, create_app
from kryon.server.auth.models import User
from kryon.server.auth.password import hash_password


class ThreadSafeTestStore(MemoryStore):
    """MemoryStore with check_same_thread=False for test use."""

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), timeout=30, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
        return self._conn


@pytest.fixture
def jwt_app_and_client(tmp_path, monkeypatch):
    """App with JWT configured + test user."""
    store = ThreadSafeTestStore(db_path=tmp_path / "auth_test.db")
    user = User(
        username="testadmin",
        email="admin@test.com",
        password_hash=hash_password("admin123"),
        role="admin",
    )
    store.create_user(user)

    config = ServerConfig(api_keys=[], jwt_secret="test-jwt-secret-key-for-testing-32c")
    app = create_app(config)

    import kryon.server.routes.clients as clients_mod
    monkeypatch.setattr(clients_mod, "_store", store)

    with TestClient(app) as c:
        yield c, user, store
    store.close()


def test_login_success(jwt_app_and_client):
    client, user, _ = jwt_app_and_client
    resp = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "admin123",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["username"] == "testadmin"
    assert data["user"]["role"] == "admin"
    assert "password_hash" not in data["user"]


def test_login_wrong_password(jwt_app_and_client):
    client, _, _ = jwt_app_and_client
    resp = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "wrong",
    })
    assert resp.status_code == 401


def test_login_nonexistent_user(jwt_app_and_client):
    client, _, _ = jwt_app_and_client
    resp = client.post("/api/auth/login", json={
        "username": "nobody",
        "password": "secret",
    })
    assert resp.status_code == 401


def test_refresh_token_flow(jwt_app_and_client):
    client, _, _ = jwt_app_and_client
    login_resp = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "admin123",
    })
    refresh = login_resp.json()["refresh_token"]
    resp = client.post("/api/auth/refresh", json={
        "refresh_token": refresh,
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_refresh_with_invalid_token(jwt_app_and_client):
    client, _, _ = jwt_app_and_client
    resp = client.post("/api/auth/refresh", json={
        "refresh_token": "bad-token",
    })
    assert resp.status_code == 401


def test_me_endpoint(jwt_app_and_client):
    client, _, _ = jwt_app_and_client
    login_resp = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "admin123",
    })
    token = login_resp.json()["access_token"]
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "testadmin"


def test_login_disabled_without_jwt():
    """Without JWT secret, login should return 501."""
    app = create_app(ServerConfig(api_keys=[]))
    with TestClient(app) as c:
        resp = c.post("/api/auth/login", json={
            "username": "admin",
            "password": "pass",
        })
    assert resp.status_code == 501
