"""Tests for scheduler DB persistence."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from kryon.server.scheduler import ScanScheduler, ScheduledJob


@pytest.fixture
def mock_store():
    """Mock store with scheduled_jobs methods."""
    store = MagicMock()
    store.save_scheduled_job = MagicMock()
    store.list_scheduled_jobs = MagicMock(return_value=[])
    store.update_scheduled_job_status = MagicMock()
    store.delete_scheduled_job = MagicMock(return_value=True)
    return store


@pytest.fixture
def scheduler():
    return ScanScheduler()


@pytest.mark.asyncio
async def test_schedule_scan_persists_to_db(scheduler, mock_store):
    with patch("kryon.server.scheduler._get_store", return_value=mock_store):
        job_id = await scheduler.schedule_scan(
            client_id="c1", agent_key="network_recon", interval_seconds=3600
        )

    assert job_id in scheduler.jobs
    mock_store.save_scheduled_job.assert_called_once()
    saved = mock_store.save_scheduled_job.call_args[0][0]
    assert saved["client_id"] == "c1"
    assert saved["agent_key"] == "network_recon"

    # Cleanup
    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_cancel_scan_updates_db(scheduler, mock_store):
    with patch("kryon.server.scheduler._get_store", return_value=mock_store):
        job_id = await scheduler.schedule_scan(client_id="c1", agent_key="recon")
        result = await scheduler.cancel_scan(job_id)

    assert result is True
    mock_store.update_scheduled_job_status.assert_called_with(job_id, "cancelled")

    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_restore_from_db_loads_jobs(scheduler, mock_store):
    mock_store.list_scheduled_jobs.return_value = [
        {
            "id": "job1",
            "client_id": "c1",
            "agent_key": "recon",
            "profile": "standard",
            "cron": "",
            "interval_seconds": 3600,
            "webhook_url": None,
            "status": "scheduled",
            "next_run": "",
            "last_run": "",
            "created_at": "2025-01-01T00:00:00",
        }
    ]

    with patch("kryon.server.scheduler._get_store", return_value=mock_store):
        count = await scheduler.restore_from_db()

    assert count == 1
    assert "job1" in scheduler.jobs
    assert scheduler.jobs["job1"].client_id == "c1"

    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_restore_from_db_skips_existing(scheduler, mock_store):
    # Pre-populate a job
    scheduler.jobs["job1"] = ScheduledJob(
        id="job1", client_id="c1", agent_key="recon"
    )
    mock_store.list_scheduled_jobs.return_value = [
        {
            "id": "job1",
            "client_id": "c1",
            "agent_key": "recon",
            "profile": "standard",
            "cron": "",
            "interval_seconds": 0,
            "webhook_url": None,
            "status": "scheduled",
            "next_run": "",
            "last_run": "",
            "created_at": "2025-01-01T00:00:00",
        }
    ]

    with patch("kryon.server.scheduler._get_store", return_value=mock_store):
        count = await scheduler.restore_from_db()

    assert count == 0

    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_restore_from_db_handles_error(scheduler):
    with patch("kryon.server.scheduler._get_store", side_effect=RuntimeError("no DB")):
        count = await scheduler.restore_from_db()

    assert count == 0


@pytest.mark.asyncio
async def test_cancel_nonexistent_job(scheduler):
    result = await scheduler.cancel_scan("nonexistent")
    assert result is False
