"""SQLite-based persistent storage for KRYON."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from kryon.engagements.models import Engagement, EngagementPhase
from kryon.memory.models import AgentExperience, Client, FindingRecord, ScanRecord

_DEFAULT_DB = Path.home() / ".kryon" / "kryon.db"

_SCHEMA_VERSION = 1

# Column whitelists for update methods to prevent SQL injection
_CLIENT_COLUMNS = {"name", "scope", "contact", "notes", "tags", "owner_user_id"}
_SCAN_COLUMNS = {"status", "completed_at", "finding_count", "risk_score", "report_id", "agent_key"}
_ENGAGEMENT_COLUMNS = {
    "client_name", "targets", "objectives", "duration_days", "status", "plan_json",
    "current_phase_id", "total_findings", "critical_findings", "high_findings",
    "risk_score", "started_at", "completed_at", "paused_at", "error",
    "stealth_level", "profile", "phase_interval_minutes",
}
_ENGAGEMENT_PHASE_COLUMNS = {
    "phase_type", "day_number", "order_index", "status", "agent_key", "scan_id",
    "targets_subset", "config_json", "findings_count", "progress",
    "started_at", "completed_at", "error", "checkpoint_json", "log_messages",
}
_USER_COLUMNS = {"username", "email", "password_hash", "role", "is_active", "last_login"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope TEXT DEFAULT '[]',
    contact TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    tags TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    agent_key TEXT DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT DEFAULT 'running',
    finding_count INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0.0,
    report_id TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    finding_json TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER DEFAULT 1,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS agent_experience (
    id TEXT PRIMARY KEY,
    agent_key TEXT NOT NULL,
    target_type TEXT DEFAULT '',
    strategy TEXT DEFAULT '',
    tools_effective TEXT DEFAULT '[]',
    tools_ineffective TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_client ON scans(client_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_client ON findings(client_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_experience_agent ON agent_experience(agent_key);

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    targets TEXT DEFAULT '[]',
    objectives TEXT DEFAULT '[]',
    duration_days INTEGER DEFAULT 5,
    status TEXT DEFAULT 'created',
    plan_json TEXT DEFAULT '',
    current_phase_id TEXT,
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    paused_at TEXT,
    error TEXT,
    stealth_level TEXT DEFAULT 'normal',
    profile TEXT DEFAULT 'enterprise_deep',
    phase_interval_minutes INTEGER DEFAULT 30
);

CREATE TABLE IF NOT EXISTS engagement_phases (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    phase_type TEXT NOT NULL,
    day_number INTEGER DEFAULT 1,
    order_index INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    agent_key TEXT NOT NULL,
    scan_id TEXT,
    targets_subset TEXT DEFAULT '[]',
    config_json TEXT DEFAULT '{}',
    findings_count INTEGER DEFAULT 0,
    progress REAL DEFAULT 0.0,
    started_at TEXT,
    completed_at TEXT,
    error TEXT,
    checkpoint_json TEXT DEFAULT '{}',
    log_messages TEXT DEFAULT '[]',
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
CREATE INDEX IF NOT EXISTS idx_engagements_created ON engagements(created_at);
CREATE INDEX IF NOT EXISTS idx_phases_engagement ON engagement_phases(engagement_id);
CREATE INDEX IF NOT EXISTS idx_phases_status ON engagement_phases(status);
"""


class MemoryStore:
    """SQLite-based persistent storage for KRYON."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._ensure_tables()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), timeout=30)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
        return self._conn

    def _ensure_tables(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        # Check version and run migrations
        cur = conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cur.fetchone()
        if row is None:
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (_SCHEMA_VERSION,))
            conn.commit()
            current_version = _SCHEMA_VERSION
        else:
            current_version = row["version"]
        from kryon.memory.migrations import run_migrations
        run_migrations(conn, current_version)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def backup(self, destination_path: Path) -> None:
        """Create a backup of the database using SQLite online backup API."""
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._get_conn()
        dst = sqlite3.connect(str(destination_path))
        try:
            conn.backup(dst)
        finally:
            dst.close()

    # -----------------------------------------------------------------------
    # Client CRUD
    # -----------------------------------------------------------------------
    def create_client(self, client: Client) -> Client:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO clients (id, name, scope, contact, notes, created_at, tags) VALUES (?,?,?,?,?,?,?)",
            (
                client.id,
                client.name,
                json.dumps(client.scope),
                client.contact,
                client.notes,
                client.created_at,
                json.dumps(client.tags),
            ),
        )
        conn.commit()
        return client

    def get_client(self, client_id: str) -> Client | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            return None
        return Client(
            id=row["id"],
            name=row["name"],
            scope=json.loads(row["scope"]),
            contact=row["contact"],
            notes=row["notes"],
            created_at=row["created_at"],
            tags=json.loads(row["tags"]),
        )

    def list_clients(self) -> list[Client]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM clients ORDER BY created_at DESC").fetchall()
        return [
            Client(
                id=r["id"],
                name=r["name"],
                scope=json.loads(r["scope"]),
                contact=r["contact"],
                notes=r["notes"],
                created_at=r["created_at"],
                tags=json.loads(r["tags"]),
            )
            for r in rows
        ]

    def update_client(self, client_id: str, **kwargs: str) -> Client | None:
        """Update client fields. Only keys in _CLIENT_COLUMNS are accepted."""
        client = self.get_client(client_id)
        if client is None:
            return None
        updates = []
        params = []
        for key, value in kwargs.items():
            if key not in _CLIENT_COLUMNS:
                continue
            if key in ("scope", "tags"):
                value = json.dumps(value)
            updates.append(f"{key} = ?")
            params.append(value)
        if updates:
            params.append(client_id)
            conn = self._get_conn()
            conn.execute(f"UPDATE clients SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
        return self.get_client(client_id)

    def delete_client(self, client_id: str) -> bool:
        conn = self._get_conn()
        conn.execute("DELETE FROM findings WHERE client_id = ?", (client_id,))
        conn.execute("DELETE FROM scans WHERE client_id = ?", (client_id,))
        cur = conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        conn.commit()
        return cur.rowcount > 0

    # -----------------------------------------------------------------------
    # Scan Records
    # -----------------------------------------------------------------------
    def create_scan(self, scan: ScanRecord) -> ScanRecord:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO scans (id, client_id, agent_key, started_at, completed_at, status, finding_count, risk_score, report_id) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                scan.id,
                scan.client_id,
                scan.agent_key,
                scan.started_at,
                scan.completed_at,
                scan.status,
                scan.finding_count,
                scan.risk_score,
                scan.report_id,
            ),
        )
        conn.commit()
        return scan

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        return ScanRecord(
            id=row["id"],
            client_id=row["client_id"],
            agent_key=row["agent_key"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            finding_count=row["finding_count"],
            risk_score=row["risk_score"],
            report_id=row["report_id"],
        )

    def list_scans(self, client_id: str | None = None) -> list[ScanRecord]:
        conn = self._get_conn()
        if client_id:
            rows = conn.execute(
                "SELECT * FROM scans WHERE client_id = ? ORDER BY started_at DESC", (client_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [
            ScanRecord(
                id=r["id"],
                client_id=r["client_id"],
                agent_key=r["agent_key"],
                started_at=r["started_at"],
                completed_at=r["completed_at"],
                status=r["status"],
                finding_count=r["finding_count"],
                risk_score=r["risk_score"],
                report_id=r["report_id"],
            )
            for r in rows
        ]

    def update_scan(self, scan_id: str, **kwargs) -> ScanRecord | None:
        """Update scan fields. Only keys in _SCAN_COLUMNS are accepted."""
        scan = self.get_scan(scan_id)
        if scan is None:
            return None
        updates = []
        params = []
        for key, value in kwargs.items():
            if key not in _SCAN_COLUMNS:
                continue
            updates.append(f"{key} = ?")
            params.append(value)
        if updates:
            params.append(scan_id)
            conn = self._get_conn()
            conn.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
        return self.get_scan(scan_id)

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------
    def save_finding(self, finding: FindingRecord) -> FindingRecord:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO findings (id, scan_id, client_id, finding_json, status, first_seen, last_seen, occurrences) VALUES (?,?,?,?,?,?,?,?)",
            (
                finding.id,
                finding.scan_id,
                finding.client_id,
                finding.finding_json,
                finding.status,
                finding.first_seen,
                finding.last_seen,
                finding.occurrences,
            ),
        )
        conn.commit()
        return finding

    def get_findings(self, scan_id: str) -> list[FindingRecord]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY first_seen DESC", (scan_id,)).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_client_findings(self, client_id: str, status: str | None = None) -> list[FindingRecord]:
        conn = self._get_conn()
        if status:
            rows = conn.execute(
                "SELECT * FROM findings WHERE client_id = ? AND status = ? ORDER BY first_seen DESC",
                (client_id, status),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE client_id = ? ORDER BY first_seen DESC",
                (client_id,),
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def update_finding_status(self, finding_id: str, status: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        conn.commit()
        return cur.rowcount > 0

    def get_finding_history(self, client_id: str, cve_id: str) -> list[FindingRecord]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE client_id = ? AND finding_json LIKE ? ORDER BY first_seen",
            (client_id, f"%{cve_id}%"),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    # -----------------------------------------------------------------------
    # Agent Experience
    # -----------------------------------------------------------------------
    def save_experience(self, exp: AgentExperience) -> AgentExperience:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO agent_experience (id, agent_key, target_type, strategy, tools_effective, tools_ineffective, notes, timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (
                exp.id,
                exp.agent_key,
                exp.target_type,
                exp.strategy,
                json.dumps(exp.tools_effective),
                json.dumps(exp.tools_ineffective),
                exp.notes,
                exp.timestamp,
            ),
        )
        conn.commit()
        return exp

    def get_experience(self, agent_key: str, target_type: str = "") -> list[AgentExperience]:
        conn = self._get_conn()
        if target_type:
            rows = conn.execute(
                "SELECT * FROM agent_experience WHERE agent_key = ? AND target_type = ? ORDER BY timestamp DESC",
                (agent_key, target_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM agent_experience WHERE agent_key = ? ORDER BY timestamp DESC",
                (agent_key,),
            ).fetchall()
        return [
            AgentExperience(
                id=r["id"],
                agent_key=r["agent_key"],
                target_type=r["target_type"],
                strategy=r["strategy"],
                tools_effective=json.loads(r["tools_effective"]),
                tools_ineffective=json.loads(r["tools_ineffective"]),
                notes=r["notes"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    # -----------------------------------------------------------------------
    # Engagements
    # -----------------------------------------------------------------------
    def create_engagement(self, eng: Engagement) -> Engagement:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO engagements (id, client_name, targets, objectives, duration_days, status, plan_json, current_phase_id, total_findings, critical_findings, high_findings, risk_score, created_at, started_at, completed_at, paused_at, error, stealth_level, profile, phase_interval_minutes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                eng.id, eng.client_name, json.dumps(eng.targets),
                json.dumps(eng.objectives), eng.duration_days, eng.status.value,
                eng.plan_json, eng.current_phase_id, eng.total_findings,
                eng.critical_findings, eng.high_findings, eng.risk_score,
                eng.created_at, eng.started_at, eng.completed_at, eng.paused_at,
                eng.error, eng.stealth_level, eng.profile, eng.phase_interval_minutes,
            ),
        )
        conn.commit()
        return eng

    def get_engagement(self, engagement_id: str) -> Engagement | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_engagement(row)

    def list_engagements(self, status_filter: list[str] | None = None) -> list[Engagement]:
        conn = self._get_conn()
        if status_filter:
            placeholders = ",".join("?" for _ in status_filter)
            rows = conn.execute(
                f"SELECT * FROM engagements WHERE status IN ({placeholders}) ORDER BY created_at DESC",
                status_filter,
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM engagements ORDER BY created_at DESC").fetchall()
        return [self._row_to_engagement(r) for r in rows]

    def update_engagement(self, engagement_id: str, **kwargs) -> Engagement | None:
        """Update engagement fields. Only keys in _ENGAGEMENT_COLUMNS are accepted."""
        eng = self.get_engagement(engagement_id)
        if eng is None:
            return None
        updates = []
        params = []
        for key, value in kwargs.items():
            if key not in _ENGAGEMENT_COLUMNS:
                continue
            if key in ("targets", "objectives"):
                value = json.dumps(value)
            elif key == "status" and hasattr(value, "value"):
                value = value.value
            updates.append(f"{key} = ?")
            params.append(value)
        if updates:
            params.append(engagement_id)
            conn = self._get_conn()
            conn.execute(f"UPDATE engagements SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
        return self.get_engagement(engagement_id)

    def delete_engagement(self, engagement_id: str) -> bool:
        conn = self._get_conn()
        conn.execute("DELETE FROM engagement_phases WHERE engagement_id = ?", (engagement_id,))
        cur = conn.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
        conn.commit()
        return cur.rowcount > 0

    def _row_to_engagement(self, row: sqlite3.Row) -> Engagement:
        return Engagement(
            id=row["id"], client_name=row["client_name"],
            targets=json.loads(row["targets"]),
            objectives=json.loads(row["objectives"]),
            duration_days=row["duration_days"], status=row["status"],
            plan_json=row["plan_json"] or "",
            current_phase_id=row["current_phase_id"],
            total_findings=row["total_findings"],
            critical_findings=row["critical_findings"],
            high_findings=row["high_findings"],
            risk_score=row["risk_score"], created_at=row["created_at"],
            started_at=row["started_at"], completed_at=row["completed_at"],
            paused_at=row["paused_at"], error=row["error"],
            stealth_level=row["stealth_level"], profile=row["profile"],
            phase_interval_minutes=row["phase_interval_minutes"],
        )

    # -----------------------------------------------------------------------
    # Engagement Phases
    # -----------------------------------------------------------------------
    def create_engagement_phase(self, phase: EngagementPhase) -> EngagementPhase:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO engagement_phases (id, engagement_id, phase_type, day_number, order_index, status, agent_key, scan_id, targets_subset, config_json, findings_count, progress, started_at, completed_at, error, checkpoint_json, log_messages) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                phase.id, phase.engagement_id, phase.phase_type.value,
                phase.day_number, phase.order_index, phase.status.value,
                phase.agent_key, phase.scan_id, phase.targets_subset,
                phase.config_json, phase.findings_count, phase.progress,
                phase.started_at, phase.completed_at, phase.error,
                phase.checkpoint_json, phase.log_messages,
            ),
        )
        conn.commit()
        return phase

    def get_engagement_phases(self, engagement_id: str) -> list[EngagementPhase]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM engagement_phases WHERE engagement_id = ? ORDER BY day_number, order_index",
            (engagement_id,),
        ).fetchall()
        return [self._row_to_phase(r) for r in rows]

    def get_engagement_phase(self, phase_id: str) -> EngagementPhase | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM engagement_phases WHERE id = ?", (phase_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_phase(row)

    def update_engagement_phase(self, phase_id: str, **kwargs) -> EngagementPhase | None:
        """Update engagement phase fields. Only keys in _ENGAGEMENT_PHASE_COLUMNS are accepted."""
        phase = self.get_engagement_phase(phase_id)
        if phase is None:
            return None
        updates = []
        params = []
        for key, value in kwargs.items():
            if key not in _ENGAGEMENT_PHASE_COLUMNS:
                continue
            if key in ("phase_type", "status") and hasattr(value, "value"):
                value = value.value
            updates.append(f"{key} = ?")
            params.append(value)
        if updates:
            params.append(phase_id)
            conn = self._get_conn()
            conn.execute(f"UPDATE engagement_phases SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
        return self.get_engagement_phase(phase_id)

    def _row_to_phase(self, row: sqlite3.Row) -> EngagementPhase:
        return EngagementPhase(
            id=row["id"], engagement_id=row["engagement_id"],
            phase_type=row["phase_type"], day_number=row["day_number"],
            order_index=row["order_index"], status=row["status"],
            agent_key=row["agent_key"], scan_id=row["scan_id"],
            targets_subset=row["targets_subset"],
            config_json=row["config_json"],
            findings_count=row["findings_count"], progress=row["progress"],
            started_at=row["started_at"], completed_at=row["completed_at"],
            error=row["error"], checkpoint_json=row["checkpoint_json"] or "{}",
            log_messages=row["log_messages"] or "[]",
        )

    # -----------------------------------------------------------------------
    # Users
    # -----------------------------------------------------------------------
    def create_user(self, user) -> None:
        """Create a new user. Accepts a User model from auth.models."""
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, last_login) VALUES (?,?,?,?,?,?,?,?)",
            (user.id, user.username, user.email, user.password_hash,
             user.role, int(user.is_active), user.created_at, user.last_login),
        )
        conn.commit()

    def get_user_by_username(self, username: str):
        """Get a user by username. Returns User or None."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def get_user_by_id(self, user_id: str):
        """Get a user by ID. Returns User or None."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def list_users(self) -> list:
        """List all users."""
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return [self._row_to_user(r) for r in rows]

    def update_user(self, user_id: str, **kwargs) -> bool:
        """Update user fields. Only keys in _USER_COLUMNS are accepted. Returns True if updated."""
        updates = []
        params = []
        for key, value in kwargs.items():
            if key not in _USER_COLUMNS:
                continue
            if key == "is_active":
                value = int(value)
            updates.append(f"{key} = ?")
            params.append(value)
        if not updates:
            return False
        params.append(user_id)
        conn = self._get_conn()
        cur = conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
        return cur.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        """Delete a user and their client access entries."""
        conn = self._get_conn()
        conn.execute("DELETE FROM user_client_access WHERE user_id = ?", (user_id,))
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0

    def get_user_client_ids(self, user_id: str) -> list[str]:
        """Get list of client IDs a user can access."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT client_id FROM user_client_access WHERE user_id = ?", (user_id,)
        ).fetchall()
        return [r["client_id"] for r in rows]

    def assign_client_to_user(self, user_id: str, client_id: str) -> None:
        """Grant a user access to a client."""
        conn = self._get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO user_client_access (user_id, client_id) VALUES (?,?)",
            (user_id, client_id),
        )
        conn.commit()

    def remove_client_from_user(self, user_id: str, client_id: str) -> None:
        """Revoke a user's access to a client."""
        conn = self._get_conn()
        conn.execute(
            "DELETE FROM user_client_access WHERE user_id = ? AND client_id = ?",
            (user_id, client_id),
        )
        conn.commit()

    def _row_to_user(self, row: sqlite3.Row):
        """Convert a DB row to a User model."""
        from kryon.server.auth.models import User
        return User(
            id=row["id"], username=row["username"], email=row["email"],
            password_hash=row["password_hash"], role=row["role"],
            is_active=bool(row["is_active"]), created_at=row["created_at"],
            last_login=row["last_login"],
        )

    # -----------------------------------------------------------------------
    # Audit Log
    # -----------------------------------------------------------------------
    def write_audit_log(self, entry: dict) -> None:
        """Write an audit log entry."""
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO audit_log (id, timestamp, user_id, username, action, resource_type, resource_id, details, ip_address, request_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (entry["id"], entry["timestamp"], entry.get("user_id"), entry.get("username"),
             entry["action"], entry["resource_type"], entry.get("resource_id"),
             json.dumps(entry.get("details", {})), entry.get("ip_address"), entry.get("request_id")),
        )
        conn.commit()

    def get_audit_logs(self, limit: int = 100, user_id: str | None = None,
                       action: str | None = None, resource_type: str | None = None) -> list[dict]:
        """Query audit logs with optional filters."""
        conn = self._get_conn()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        if resource_type:
            query += " AND resource_type = ?"
            params.append(resource_type)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------
    def _row_to_finding(self, row: sqlite3.Row) -> FindingRecord:
        return FindingRecord(
            id=row["id"],
            scan_id=row["scan_id"],
            client_id=row["client_id"],
            finding_json=row["finding_json"],
            status=row["status"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            occurrences=row["occurrences"],
        )
