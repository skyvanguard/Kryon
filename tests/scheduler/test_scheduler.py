"""F135 — Scheduler tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kryon.scheduler import ScheduledJob, Scheduler, parse_simple_cron
from kryon.scheduler.scheduler import cron_matches

# ---------------------------------------------------------------------------
# parse_simple_cron
# ---------------------------------------------------------------------------


def test_parse_all_stars():
    minute, hour, dom, month, dow = parse_simple_cron("* * * * *")
    assert minute is None and hour is None and dom is None and month is None and dow is None


def test_parse_specific_minute():
    minute, *_ = parse_simple_cron("0 * * * *")
    assert minute == {0}


def test_parse_list_of_minutes():
    minute, *_ = parse_simple_cron("0,15,30,45 * * * *")
    assert minute == {0, 15, 30, 45}


def test_parse_rejects_wrong_field_count():
    with pytest.raises(ValueError):
        parse_simple_cron("0 6 * *")  # only 4 fields


def test_parse_supports_ranges():
    _, hour, *_ = parse_simple_cron("0 6-8 * * *")
    assert hour == {6, 7, 8}


def test_parse_supports_steps():
    minute, *_ = parse_simple_cron("*/15 * * * *")
    assert minute == {0, 15, 30, 45}


def test_parse_supports_range_with_step():
    minute, *_ = parse_simple_cron("0-30/10 * * * *")
    assert minute == {0, 10, 20, 30}


def test_parse_every_4_hours():
    _, hour, *_ = parse_simple_cron("0 */4 * * *")
    assert hour == {0, 4, 8, 12, 16, 20}


def test_parse_rejects_out_of_range():
    with pytest.raises(ValueError):
        parse_simple_cron("99 * * * *")  # minute > 59


def test_parse_rejects_inverted_range():
    with pytest.raises(ValueError):
        parse_simple_cron("0 8-6 * * *")


def test_parse_rejects_named_alias():
    with pytest.raises(ValueError):
        parse_simple_cron("0 6 * * MON")


# ---------------------------------------------------------------------------
# cron_matches
# ---------------------------------------------------------------------------


def test_match_every_minute():
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("* * * * *", dt)


def test_match_specific_hour():
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 * * *", dt)
    assert not cron_matches("0 7 * * *", dt)


def test_match_specific_day_of_month():
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 14 * *", dt)
    assert not cron_matches("0 6 15 * *", dt)


def test_match_day_of_week():
    # 2026-05-14 is a Thursday. Cron weekday Sunday=0..Saturday=6,
    # so Thursday=4.
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 * * 4", dt)
    assert not cron_matches("0 6 * * 0", dt)


# ---------------------------------------------------------------------------
# Scheduler persistence + CRUD
# ---------------------------------------------------------------------------


def test_load_missing_returns_empty(tmp_path):
    sched = Scheduler.load(tmp_path / "no.json")
    assert sched.jobs == []


def test_add_then_save_then_load_roundtrip(tmp_path):
    path = tmp_path / "schedule.json"
    sched = Scheduler.load(path)
    sched.add_job(ScheduledJob(job_id="j1", target="x.com", cron="0 6 * * *", objective="recon"))
    sched.save()
    re = Scheduler.load(path)
    assert len(re.jobs) == 1
    assert re.jobs[0].job_id == "j1"


def test_add_replaces_existing_job_id(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="j1", target="x.com", cron="0 6 * * *"))
    sched.add_job(ScheduledJob(job_id="j1", target="x.com", cron="0 7 * * *"))
    assert len(sched.jobs) == 1
    assert sched.jobs[0].cron == "0 7 * * *"


def test_add_rejects_bad_cron(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    with pytest.raises(ValueError):
        sched.add_job(ScheduledJob(job_id="j", target="x", cron="not-cron"))


def test_remove_job(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="j1", target="x", cron="* * * * *"))
    assert sched.remove_job("j1") is True
    assert sched.jobs == []
    assert sched.remove_job("not-there") is False


# ---------------------------------------------------------------------------
# due_jobs
# ---------------------------------------------------------------------------


def test_due_returns_jobs_matching_cron(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="every-minute", target="x", cron="* * * * *"))
    sched.add_job(ScheduledJob(job_id="six-am", target="x", cron="0 6 * * *"))
    now = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    due_ids = {j.job_id for j in sched.due_jobs(now=now)}
    assert "every-minute" in due_ids
    assert "six-am" in due_ids


def test_due_skips_disabled_jobs(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="off", target="x", cron="* * * * *", enabled=False))
    now = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert sched.due_jobs(now=now) == []


def test_due_skips_if_last_run_same_minute(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(
        ScheduledJob(
            job_id="j",
            target="x",
            cron="* * * * *",
            last_run_ts="2026-05-14T06:00:30Z",
        )
    )
    # Same minute as last_run → not due.
    now = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert sched.due_jobs(now=now) == []
    # Next minute → due.
    now2 = datetime(2026, 5, 14, 6, 1, tzinfo=timezone.utc)
    assert len(sched.due_jobs(now=now2)) == 1


def test_mark_run_updates_last_run(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="j", target="x", cron="* * * * *"))
    when = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    sched.mark_run("j", when=when)
    assert sched.jobs[0].last_run_ts == "2026-05-14T06:00:00Z"


def test_mark_run_preserves_sweep_fields(tmp_path):
    # Regression guard: mark_run must not drop kind/framework/client/
    # dry_run_only (the old manual reconstruction would have).
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(
        ScheduledJob(
            job_id="sweep1",
            target="10.0.0.0/24",
            cron="* * * * *",
            kind="sweep",
            framework="pci_dss",
            client="example",
            dry_run_only=False,
        )
    )
    sched.mark_run("sweep1", when=datetime(2026, 5, 14, 2, 0, tzinfo=timezone.utc))
    j = sched.jobs[0]
    assert j.kind == "sweep"
    assert j.framework == "pci_dss"
    assert j.client == "example"
    assert j.dry_run_only is False
    assert j.last_run_ts == "2026-05-14T02:00:00Z"


def test_build_cmd_engage_includes_dry_run_only_by_default():
    from kryon.cli.schedule_cmd import _build_job_cmd

    job = ScheduledJob(job_id="j", target="10.0.1.5", cron="0 2 * * *", framework="pci_dss")
    cmd = _build_job_cmd(job, notify_drift=True)
    assert "engage" in cmd
    assert "10.0.1.5" in cmd
    assert "--dry-run-only" in cmd
    assert "--framework" in cmd and "pci_dss" in cmd
    assert "--notify-drift" in cmd


def test_build_cmd_engage_drops_dry_run_when_remediation_allowed():
    from kryon.cli.schedule_cmd import _build_job_cmd

    job = ScheduledJob(job_id="j", target="10.0.1.5", cron="0 2 * * *", dry_run_only=False)
    cmd = _build_job_cmd(job, notify_drift=False)
    assert "--dry-run-only" not in cmd


def test_build_cmd_sweep_forks_sweep():
    from kryon.cli.schedule_cmd import _build_job_cmd

    job = ScheduledJob(
        job_id="seg", target="10.0.0.0/24", cron="0 2 * * *", kind="sweep", framework="cis", client="acme"
    )
    cmd = _build_job_cmd(job, notify_drift=False)
    assert "sweep" in cmd
    assert "10.0.0.0/24" in cmd
    assert "--client" in cmd and "acme" in cmd
    assert "--framework" in cmd and "cis" in cmd
    assert "engage" not in cmd


# --- Fase B: kind="update" — feed refresh job (growing determinism) --------


def test_build_cmd_update_forks_kryon_update():
    from kryon.cli.schedule_cmd import _build_job_cmd

    job = ScheduledJob(job_id="feeds", target="", cron="0 1 * * *", kind="update")
    cmd = _build_job_cmd(job, notify_drift=True)
    assert cmd[-1] == "update"
    assert "engage" not in cmd
    assert "sweep" not in cmd
    # drift alerting is meaningless for a feed refresh
    assert "--notify-drift" not in cmd


def _add_args(**over):
    import argparse

    base = dict(
        schedule_action="add", id="j", target="", subnet="", update_job=False,
        cron="0 2 * * *", objective="", framework="", client="scheduled", allow_remediation=False,
    )
    base.update(over)
    return argparse.Namespace(**base)


def test_run_schedule_add_update_creates_update_job(tmp_path, monkeypatch):
    from kryon.cli.schedule_cmd import run_schedule_command
    from kryon.scheduler import Scheduler

    monkeypatch.setenv("KRYON_SCHEDULE_PATH", str(tmp_path / "sched.json"))
    assert run_schedule_command(_add_args(id="nightly-feeds", update_job=True)) == 0

    job = Scheduler.load().get_job("nightly-feeds")
    assert job is not None
    assert job.kind == "update"
    assert job.target == ""


def test_run_schedule_add_update_rejects_target(tmp_path, monkeypatch):
    from kryon.cli.schedule_cmd import run_schedule_command

    monkeypatch.setenv("KRYON_SCHEDULE_PATH", str(tmp_path / "sched.json"))
    assert run_schedule_command(_add_args(update_job=True, target="10.0.0.1")) == 2
