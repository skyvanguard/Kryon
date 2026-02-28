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
    8: [
        """CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            client_id TEXT DEFAULT '',
            asset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            metadata_json TEXT DEFAULT '{}',
            first_seen TEXT NOT NULL,
            last_seen TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_assets_client ON assets(client_id)",
        "CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type)",
        "CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets(identifier)",
        """CREATE TABLE IF NOT EXISTS asset_changes (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value TEXT DEFAULT '',
            new_value TEXT DEFAULT '',
            detected_at TEXT NOT NULL,
            scan_id TEXT DEFAULT '',
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_asset_changes_asset ON asset_changes(asset_id)",
    ],
    9: [
        """CREATE TABLE IF NOT EXISTS iocs (
            id TEXT PRIMARY KEY,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            source TEXT DEFAULT '',
            threat_score REAL DEFAULT 0.5,
            tags TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT,
            ttl_days INTEGER DEFAULT 90,
            enrichment_json TEXT DEFAULT '{}',
            UNIQUE(ioc_type, ioc_value)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_score ON iocs(threat_score)",
    ],
    10: [
        """CREATE TABLE IF NOT EXISTS notification_channels (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            channel_type TEXT NOT NULL,
            config_json TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            created_by TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS notification_rules (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            severity_filter TEXT DEFAULT '',
            client_filter TEXT DEFAULT '',
            channel_ids TEXT DEFAULT '[]',
            digest_mode TEXT DEFAULT 'immediate',
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS notification_log (
            id TEXT PRIMARY KEY,
            channel_id TEXT,
            event_type TEXT NOT NULL,
            payload_json TEXT DEFAULT '{}',
            sent_at TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            error_message TEXT DEFAULT ''
        )""",
        "CREATE INDEX IF NOT EXISTS idx_notification_log_sent ON notification_log(sent_at)",
    ],
    11: [
        "ALTER TABLE findings ADD COLUMN assigned_to TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN assigned_at TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN sla_deadline TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN remediation_notes TEXT DEFAULT '[]'",
        "ALTER TABLE findings ADD COLUMN remediated_at TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN remediated_by TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN retest_status TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN retest_scan_id TEXT DEFAULT NULL",
        "ALTER TABLE findings ADD COLUMN priority TEXT DEFAULT 'medium'",
        """CREATE TABLE IF NOT EXISTS finding_history (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value TEXT DEFAULT '',
            new_value TEXT DEFAULT '',
            changed_by TEXT DEFAULT '',
            changed_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_finding_history_finding ON finding_history(finding_id)",
    ],
    12: [
        "ALTER TABLE assets ADD COLUMN criticality TEXT DEFAULT 'medium'",
        "ALTER TABLE assets ADD COLUMN exposure TEXT DEFAULT 'internal'",
    ],
    13: [
        """CREATE TABLE IF NOT EXISTS report_brandings (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            logo_url TEXT DEFAULT '',
            primary_color TEXT DEFAULT '#00d4ff',
            company_name TEXT DEFAULT '',
            footer_text TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT
        )""",
    ],
    14: [
        """CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            label TEXT DEFAULT '',
            encrypted_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT,
            last_used_at TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_credentials_client ON credentials(client_id)",
        """CREATE TABLE IF NOT EXISTS onboarding_sessions (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            current_step INTEGER DEFAULT 1,
            data_json TEXT DEFAULT '{}',
            started_at TEXT NOT NULL,
            completed_at TEXT
        )""",
    ],
    15: [
        """CREATE TABLE IF NOT EXISTS licenses (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            license_key TEXT NOT NULL,
            tier TEXT DEFAULT 'free',
            features TEXT DEFAULT '[]',
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )""",
        "CREATE INDEX IF NOT EXISTS idx_licenses_tenant ON licenses(tenant_id)",
        """CREATE TABLE IF NOT EXISTS usage_metering (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            amount INTEGER DEFAULT 1,
            recorded_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage_metering(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_usage_recorded ON usage_metering(recorded_at)",
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
