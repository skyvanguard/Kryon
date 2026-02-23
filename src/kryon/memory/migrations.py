"""Simple schema migrations for MemoryStore."""

from __future__ import annotations

import sqlite3


def run_migrations(conn: sqlite3.Connection, current_version: int) -> int:
    """Run any pending migrations. Returns new version."""
    migrations = {
        # version: migration SQL
        # 2: "ALTER TABLE clients ADD COLUMN industry TEXT DEFAULT '';",
    }

    for version in sorted(migrations.keys()):
        if version > current_version:
            conn.executescript(migrations[version])
            conn.execute("UPDATE schema_version SET version = ?", (version,))
            conn.commit()
            current_version = version

    return current_version
