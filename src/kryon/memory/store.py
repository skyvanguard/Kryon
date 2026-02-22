"""SQLite-based persistent storage for KRYON."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from kryon.memory.models import AgentExperience, Client, FindingRecord, ScanRecord

_DEFAULT_DB = Path.home() / ".kryon" / "kryon.db"

_SCHEMA_VERSION = 1

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
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _ensure_tables(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        # Check version
        cur = conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)", (_SCHEMA_VERSION,)
            )
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # -----------------------------------------------------------------------
    # Client CRUD
    # -----------------------------------------------------------------------
    def create_client(self, client: Client) -> Client:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO clients (id, name, scope, contact, notes, created_at, tags) VALUES (?,?,?,?,?,?,?)",
            (client.id, client.name, json.dumps(client.scope), client.contact, client.notes, client.created_at, json.dumps(client.tags)),
        )
        conn.commit()
        return client

    def get_client(self, client_id: str) -> Client | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            return None
        return Client(
            id=row["id"], name=row["name"], scope=json.loads(row["scope"]),
            contact=row["contact"], notes=row["notes"], created_at=row["created_at"],
            tags=json.loads(row["tags"]),
        )

    def list_clients(self) -> list[Client]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM clients ORDER BY created_at DESC").fetchall()
        return [
            Client(
                id=r["id"], name=r["name"], scope=json.loads(r["scope"]),
                contact=r["contact"], notes=r["notes"], created_at=r["created_at"],
                tags=json.loads(r["tags"]),
            )
            for r in rows
        ]

    def update_client(self, client_id: str, **kwargs: str) -> Client | None:
        client = self.get_client(client_id)
        if client is None:
            return None
        updates = []
        params = []
        for key, value in kwargs.items():
            if key in ("scope", "tags"):
                value = json.dumps(value)
            updates.append(f"{key} = ?")
            params.append(value)
        if updates:
            params.append(client_id)
            conn = self._get_conn()
            conn.execute(
                f"UPDATE clients SET {', '.join(updates)} WHERE id = ?", params
            )
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
            (scan.id, scan.client_id, scan.agent_key, scan.started_at, scan.completed_at, scan.status, scan.finding_count, scan.risk_score, scan.report_id),
        )
        conn.commit()
        return scan

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        return ScanRecord(
            id=row["id"], client_id=row["client_id"], agent_key=row["agent_key"],
            started_at=row["started_at"], completed_at=row["completed_at"],
            status=row["status"], finding_count=row["finding_count"],
            risk_score=row["risk_score"], report_id=row["report_id"],
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
                id=r["id"], client_id=r["client_id"], agent_key=r["agent_key"],
                started_at=r["started_at"], completed_at=r["completed_at"],
                status=r["status"], finding_count=r["finding_count"],
                risk_score=r["risk_score"], report_id=r["report_id"],
            )
            for r in rows
        ]

    def update_scan(self, scan_id: str, **kwargs) -> ScanRecord | None:
        scan = self.get_scan(scan_id)
        if scan is None:
            return None
        updates = []
        params = []
        for key, value in kwargs.items():
            updates.append(f"{key} = ?")
            params.append(value)
        if updates:
            params.append(scan_id)
            conn = self._get_conn()
            conn.execute(
                f"UPDATE scans SET {', '.join(updates)} WHERE id = ?", params
            )
            conn.commit()
        return self.get_scan(scan_id)

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------
    def save_finding(self, finding: FindingRecord) -> FindingRecord:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO findings (id, scan_id, client_id, finding_json, status, first_seen, last_seen, occurrences) VALUES (?,?,?,?,?,?,?,?)",
            (finding.id, finding.scan_id, finding.client_id, finding.finding_json, finding.status, finding.first_seen, finding.last_seen, finding.occurrences),
        )
        conn.commit()
        return finding

    def get_findings(self, scan_id: str) -> list[FindingRecord]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY first_seen DESC", (scan_id,)
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_client_findings(
        self, client_id: str, status: str | None = None
    ) -> list[FindingRecord]:
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
        cur = conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?", (status, finding_id)
        )
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
            (exp.id, exp.agent_key, exp.target_type, exp.strategy, json.dumps(exp.tools_effective), json.dumps(exp.tools_ineffective), exp.notes, exp.timestamp),
        )
        conn.commit()
        return exp

    def get_experience(
        self, agent_key: str, target_type: str = ""
    ) -> list[AgentExperience]:
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
                id=r["id"], agent_key=r["agent_key"], target_type=r["target_type"],
                strategy=r["strategy"], tools_effective=json.loads(r["tools_effective"]),
                tools_ineffective=json.loads(r["tools_ineffective"]),
                notes=r["notes"], timestamp=r["timestamp"],
            )
            for r in rows
        ]

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------
    def _row_to_finding(self, row: sqlite3.Row) -> FindingRecord:
        return FindingRecord(
            id=row["id"], scan_id=row["scan_id"], client_id=row["client_id"],
            finding_json=row["finding_json"], status=row["status"],
            first_seen=row["first_seen"], last_seen=row["last_seen"],
            occurrences=row["occurrences"],
        )
