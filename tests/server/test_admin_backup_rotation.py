"""Tests for admin backup rotation and export endpoints."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from kryon.memory.store import MemoryStore


@pytest.fixture
def backup_dir(tmp_path):
    """Create a temp backup dir with sample backups."""
    bd = tmp_path / "backups"
    bd.mkdir()
    for i in range(5):
        f = bd / f"kryon_backup_2025010{i}_000000.db"
        f.write_bytes(b"x" * (i + 1) * 100)
    return bd


class _SafeStore(MemoryStore):
    """Cross-thread safe store for TestClient."""

    def _get_conn(self):
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), timeout=30, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    """Create test app with auth disabled (api_keys=[])."""
    from kryon.server.app import create_app
    from kryon.server.config import ServerConfig
    import kryon.server.deps as deps_mod

    store = _SafeStore(db_path=tmp_path / "test.db")
    monkeypatch.setattr(deps_mod, "_store", store)

    config = ServerConfig(api_keys=[])
    app = create_app(config)
    with TestClient(app) as client:
        yield client
    store.close()


def test_list_backups(admin_client, backup_dir, monkeypatch):
    monkeypatch.setattr("kryon.server.routes.admin._BACKUP_DIR", backup_dir)
    resp = admin_client.get("/api/v1/admin/backups")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 5
    assert "filename" in data[0]
    assert "size_bytes" in data[0]


def test_list_backups_empty_dir(admin_client, tmp_path, monkeypatch):
    empty = tmp_path / "empty_backups"
    empty.mkdir()
    monkeypatch.setattr("kryon.server.routes.admin._BACKUP_DIR", empty)
    resp = admin_client.get("/api/v1/admin/backups")
    assert resp.status_code == 200
    assert resp.json() == []


def test_delete_backup(admin_client, backup_dir, monkeypatch):
    monkeypatch.setattr("kryon.server.routes.admin._BACKUP_DIR", backup_dir)
    resp = admin_client.delete("/api/v1/admin/backups/kryon_backup_20250100_000000.db")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert not (backup_dir / "kryon_backup_20250100_000000.db").exists()


def test_delete_backup_path_traversal(admin_client, backup_dir, monkeypatch):
    monkeypatch.setattr("kryon.server.routes.admin._BACKUP_DIR", backup_dir)
    resp = admin_client.delete("/api/v1/admin/backups/..%2F..%2Fetc%2Fpasswd")
    # FastAPI decodes %2F→/ so path becomes ../../etc/passwd which
    # either doesn't match the route (405) or hits our traversal check (400).
    assert resp.status_code in (400, 404, 405, 422)


def test_rotate_backups(admin_client, backup_dir, monkeypatch):
    monkeypatch.setattr("kryon.server.routes.admin._BACKUP_DIR", backup_dir)
    resp = admin_client.post("/api/v1/admin/backup/rotate", json={"keep": 2})
    assert resp.status_code == 200
    data = resp.json()
    assert data["deleted_count"] == 3
    assert data["kept"] == 2
    # Only 2 files remain
    remaining = list(backup_dir.glob("kryon_backup_*.db"))
    assert len(remaining) == 2


def test_export_table_whitelist(admin_client):
    resp = admin_client.get("/api/v1/admin/export/users")
    assert resp.status_code == 400
    assert "not exportable" in resp.json()["detail"]


def test_export_table_clients(admin_client):
    resp = admin_client.get("/api/v1/admin/export/clients")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_export_table_with_filter(admin_client):
    resp = admin_client.get("/api/v1/admin/export/clients?client_id=nonexistent")
    assert resp.status_code == 200
    assert resp.json() == []
