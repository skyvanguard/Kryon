"""Tests for scan scheduler."""

import asyncio

import pytest

from kryon.server.scheduler import ScanScheduler


@pytest.mark.asyncio
async def test_schedule_and_cancel():
    scheduler = ScanScheduler()
    job_id = await scheduler.schedule_scan(
        client_id="c1",
        agent_key="recon_scout",
        interval_seconds=0,  # one-shot
    )
    assert job_id in scheduler.jobs
    assert scheduler.jobs[job_id].status in ("scheduled", "running", "completed")

    # Cancel
    result = await scheduler.cancel_scan(job_id)
    assert result is True
    assert scheduler.jobs[job_id].status == "cancelled"
    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_list_scheduled():
    scheduler = ScanScheduler()
    await scheduler.schedule_scan(client_id="c1", agent_key="a1", interval_seconds=0)
    await scheduler.schedule_scan(client_id="c2", agent_key="a2", interval_seconds=0)
    jobs = await scheduler.list_scheduled()
    assert len(jobs) == 2
    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_cancel_nonexistent():
    scheduler = ScanScheduler()
    result = await scheduler.cancel_scan("nonexistent")
    assert result is False
    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_scan_callback():
    scheduler = ScanScheduler()
    executed = []

    # The scan callback contract is `callback(job: ScheduledJob)` — a single
    # positional job object (see ScanScheduler.run_scan_job), not **kwargs.
    async def mock_callback(job):
        executed.append(job)

    scheduler.set_scan_callback(mock_callback)
    job_id = await scheduler.schedule_scan(client_id="c1", agent_key="a1", interval_seconds=0)
    # Wait for one-shot to complete
    await asyncio.sleep(0.2)
    assert len(executed) == 1
    assert executed[0].client_id == "c1"
    await scheduler.shutdown()
