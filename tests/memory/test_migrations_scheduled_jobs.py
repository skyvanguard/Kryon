"""Regression test for the v17 scheduled_jobs column backfill.

v16 shipped `scheduled_jobs` without targets_json / frameworks_json / start_hour;
those columns were later added to the CREATE TABLE (store.py `_SCHEMA`) but no
migration was written, so DBs created at v16 lacked them and
`save_scheduled_job()` failed with "no column named targets_json". Migration v17
backfills them.
"""

from __future__ import annotations

import sqlite3

from kryon.memory.store import MemoryStore

# The scheduled_jobs table exactly as migration v16 created it — missing the
# three columns added afterwards.
_V16_SCHEDULED_JOBS = """
CREATE TABLE scheduled_jobs (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    agent_key TEXT NOT NULL,
    profile TEXT DEFAULT 'standard',
    cron TEXT DEFAULT '',
    interval_seconds INTEGER DEFAULT 0,
    webhook_url TEXT,
    status TEXT DEFAULT 'scheduled',
    next_run TEXT DEFAULT '',
    last_run TEXT DEFAULT '',
    created_at TEXT NOT NULL
)
"""


def _seed_v16_db(db_path) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO schema_version (version) VALUES (16)")
        conn.execute(_V16_SCHEDULED_JOBS)
        conn.commit()
    finally:
        conn.close()


def test_v16_db_backfills_scheduled_jobs_columns(tmp_path):
    db = tmp_path / "old.db"
    _seed_v16_db(db)

    # Opening the store runs _ensure_tables -> run_migrations -> v17 backfill.
    store = MemoryStore(db_path=db)
    try:
        cols = {row[1] for row in store._get_conn().execute("PRAGMA table_info(scheduled_jobs)")}
        assert {"targets_json", "frameworks_json", "start_hour"} <= cols

        # The exact call that used to raise "no column named targets_json".
        store.save_scheduled_job(
            {
                "id": "job-1",
                "client_id": "c1",
                "targets": ["10.0.0.1", "10.0.0.2"],
                "frameworks": ["pci_dss"],
                "start_hour": 2,
                "created_at": "2026-01-01T00:00:00",
            }
        )
        jobs = store.list_scheduled_jobs()
        assert len(jobs) == 1
        assert jobs[0]["targets"] == ["10.0.0.1", "10.0.0.2"]
        assert jobs[0]["frameworks"] == ["pci_dss"]
        assert jobs[0]["start_hour"] == 2
    finally:
        store.close()
