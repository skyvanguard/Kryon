"""Tests for the nightly scheduler pieces: the hour-alignment helper and the
scheduled_jobs store round-trip (targets/frameworks/start_hour persistence).
"""

from __future__ import annotations

from datetime import datetime, timezone

from kryon.memory.store import MemoryStore
from kryon.server.scheduler import ScheduledJob, seconds_until_hour


def test_seconds_until_hour_later_today():
    now = datetime(2026, 7, 28, 1, 0, 0, tzinfo=timezone.utc)
    assert seconds_until_hour(2, now) == 3600.0  # 01:00 -> 02:00 today


def test_seconds_until_hour_rolls_to_tomorrow():
    now = datetime(2026, 7, 28, 20, 0, 0, tzinfo=timezone.utc)
    assert seconds_until_hour(2, now) == 6 * 3600.0  # 20:00 -> 02:00 next day


def test_seconds_until_hour_zero_when_current_hour():
    now = datetime(2026, 7, 28, 2, 30, 0, tzinfo=timezone.utc)
    assert seconds_until_hour(2, now) == 0.0


def test_scheduled_job_store_roundtrip(tmp_path):
    """Targets/frameworks/start_hour must survive persist -> list -> reconstruct."""
    store = MemoryStore(db_path=tmp_path / "sched.db")
    job = ScheduledJob(
        client_id="acme",
        profile="standard",
        targets=["192.168.1.0/24", "10.0.0.5"],
        frameworks=["pci_dss", "cis_controls"],
        interval_seconds=86400,
        start_hour=2,
    )
    store.save_scheduled_job(job.model_dump())

    rows = store.list_scheduled_jobs()
    assert len(rows) == 1
    restored = ScheduledJob(**rows[0])
    assert restored.targets == ["192.168.1.0/24", "10.0.0.5"]
    assert restored.frameworks == ["pci_dss", "cis_controls"]
    assert restored.start_hour == 2
    assert restored.interval_seconds == 86400
    assert restored.client_id == "acme"
