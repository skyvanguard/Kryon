"""Simple schema migrations for MemoryStore."""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger(__name__)

# Keyed by target version number. Each entry is a list of SQL statements.
MIGRATIONS: dict[int, list[str]] = {
    2: [
        "ALTER TABLE clients ADD COLUMN owner_user_id TEXT DEFAULT NULL",
    ],
    3: [
        """CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS user_client_access (
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            PRIMARY KEY (user_id, client_id)
        )""",
    ],
    4: [
        """CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details TEXT DEFAULT '{}',
            ip_address TEXT,
            request_id TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)",
    ],
    5: [
        """CREATE TABLE IF NOT EXISTS scope_whitelist (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            created_by TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scope_client ON scope_whitelist(client_id)",
    ],
    6: [
        """CREATE TABLE IF NOT EXISTS siem_configs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            siem_type TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            token TEXT DEFAULT '',
            index_name TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            config_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT
        )""",
    ],
    7: [
        """CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            slug TEXT NOT NULL UNIQUE,
            tier TEXT DEFAULT 'free',
            is_active INTEGER DEFAULT 1,
            config_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS tenant_quotas (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            max_value INTEGER NOT NULL,
            current_value INTEGER DEFAULT 0,
            reset_at TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_tenant_quotas_tenant ON tenant_quotas(tenant_id)",
    ],
}


def run_migrations(conn: sqlite3.Connection, current_version: int) -> int:
    """Run any pending migrations. Returns new version."""
    for version in sorted(MIGRATIONS.keys()):
        if version <= current_version:
            continue
        for sql in MIGRATIONS[version]:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if "duplicate column" in msg or "already exists" in msg:
                    logger.debug("Migration v%d: skipping — %s", version, e)
                    continue
                raise
        conn.execute("UPDATE schema_version SET version = ?", (version,))
        conn.commit()
        current_version = version
        logger.info("Applied migration v%d", version)

    return current_version
