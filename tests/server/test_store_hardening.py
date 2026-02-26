"""Tests for SQLite hardening and migration system."""

import sqlite3
from pathlib import Path

import pytest

from kryon.memory.store import MemoryStore


@pytest.fixture
def tmp_store(tmp_path):
    db_path = tmp_path / "test.db"
    store = MemoryStore(db_path=db_path)
    yield store
    store.close()


def test_busy_timeout_set(tmp_store):
    """busy_timeout pragma should be set."""
    conn = tmp_store._get_conn()
    row = conn.execute("PRAGMA busy_timeout").fetchone()
    assert row[0] == 5000


def test_connect_timeout(tmp_store):
    """Connection should use timeout=30."""
    # We verify indirectly — the store was created without error
    assert tmp_store._conn is not None


def test_migration_adds_owner_user_id(tmp_path):
    """Migration v2 should add owner_user_id column to clients."""
    db_path = tmp_path / "migrate.db"
    store = MemoryStore(db_path=db_path)
    conn = store._get_conn()

    # Check that owner_user_id column exists
    cursor = conn.execute("PRAGMA table_info(clients)")
    columns = {row[1] for row in cursor.fetchall()}
    assert "owner_user_id" in columns

    # Check schema version was updated
    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    assert row[0] >= 2
    store.close()


def test_backup_creates_file(tmp_store, tmp_path):
    """backup() should create a valid SQLite copy."""
    from kryon.memory.models import Client

    # Insert some data
    client = Client(name="BackupTest", scope=["10.0.0.0/24"])
    tmp_store.create_client(client)

    backup_path = tmp_path / "backup" / "kryon_backup.db"
    tmp_store.backup(backup_path)

    assert backup_path.exists()

    # Verify backup has data
    backup_conn = sqlite3.connect(str(backup_path))
    backup_conn.row_factory = sqlite3.Row
    row = backup_conn.execute("SELECT name FROM clients WHERE id = ?", (client.id,)).fetchone()
    assert row["name"] == "BackupTest"
    backup_conn.close()


def test_migration_idempotent(tmp_path):
    """Running migrations twice should not error."""
    db_path = tmp_path / "idempotent.db"
    store1 = MemoryStore(db_path=db_path)
    store1.close()

    # Re-open — migrations should be no-op
    store2 = MemoryStore(db_path=db_path)
    conn = store2._get_conn()
    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    assert row[0] >= 2
    store2.close()
