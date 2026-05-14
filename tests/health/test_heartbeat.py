"""F142 — Heartbeat + doctor tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from kryon.health.heartbeat import (
    HeartbeatRecord,
    is_stale,
    read_heartbeat,
    run_doctor,
    write_heartbeat,
)

# ---------------------------------------------------------------------------
# write_heartbeat / read_heartbeat roundtrip
# ---------------------------------------------------------------------------


def test_write_then_read(tmp_path):
    path = tmp_path / "hb.json"
    written = write_heartbeat(path=path, extra={"engagement": "test"})
    assert written is not None
    rec = read_heartbeat(path=path)
    assert rec is not None
    assert rec.pid > 0
    assert rec.extra["engagement"] == "test"


def test_read_missing_returns_none(tmp_path):
    assert read_heartbeat(path=tmp_path / "no.json") is None


def test_read_malformed_returns_none(tmp_path):
    p = tmp_path / "hb.json"
    p.write_text("not json", encoding="utf-8")
    assert read_heartbeat(path=p) is None


def test_write_creates_parent_dir(tmp_path):
    nested = tmp_path / "deep" / "nested" / "hb.json"
    written = write_heartbeat(path=nested)
    assert written is not None
    assert nested.exists()


def test_heartbeat_contains_timestamp_pid_hostname(tmp_path):
    p = tmp_path / "hb.json"
    write_heartbeat(path=p)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert "timestamp" in data
    assert data["pid"] > 0
    assert data["hostname"]


# ---------------------------------------------------------------------------
# is_stale
# ---------------------------------------------------------------------------


def test_is_stale_none():
    assert is_stale(None) is True


def test_is_stale_missing_timestamp():
    rec = HeartbeatRecord(timestamp="", pid=1, hostname="h")
    assert is_stale(rec) is True


def test_is_stale_fresh(tmp_path):
    p = tmp_path / "hb.json"
    write_heartbeat(path=p)
    rec = read_heartbeat(path=p)
    # Just written → fresh.
    assert is_stale(rec, threshold_minutes=10) is False


def test_is_stale_old():
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds").replace("+00:00", "Z")
    rec = HeartbeatRecord(timestamp=old, pid=1, hostname="h")
    assert is_stale(rec, threshold_minutes=10) is True


def test_is_stale_within_threshold():
    recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="seconds").replace("+00:00", "Z")
    rec = HeartbeatRecord(timestamp=recent, pid=1, hostname="h")
    assert is_stale(rec, threshold_minutes=10) is False


def test_is_stale_invalid_timestamp():
    rec = HeartbeatRecord(timestamp="not-a-date", pid=1, hostname="h")
    assert is_stale(rec) is True


# ---------------------------------------------------------------------------
# run_doctor smoke
# ---------------------------------------------------------------------------


def test_doctor_returns_list_of_results(tmp_path, monkeypatch):
    # Cd into tmp so ".kryon/..." dirs are isolated.
    monkeypatch.chdir(tmp_path)
    results = run_doctor(check_ollama=False)
    assert isinstance(results, list)
    assert len(results) >= 4  # 3 dirs + heartbeat (+ env)
    # Dir probes should pass in a fresh tmp dir.
    dir_checks = [r for r in results if r.name.startswith("dir:")]
    assert all(r.ok for r in dir_checks)


def test_doctor_flags_missing_heartbeat(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    results = run_doctor(check_ollama=False)
    hb = next(r for r in results if r.name == "heartbeat")
    assert hb.ok is False
    assert "missing" in hb.detail


def test_doctor_passes_when_heartbeat_fresh(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".kryon").mkdir()
    write_heartbeat(path=tmp_path / ".kryon" / "heartbeat.json")
    results = run_doctor(check_ollama=False)
    hb = next(r for r in results if r.name == "heartbeat")
    assert hb.ok is True


def test_doctor_flags_missing_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KRYON_MODEL", raising=False)
    results = run_doctor(check_ollama=False)
    env = next(r for r in results if r.name == "env:KRYON_MODEL")
    assert env.ok is False


def test_doctor_passes_when_env_set(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KRYON_MODEL", "kryon-14b")
    results = run_doctor(check_ollama=False)
    env = next(r for r in results if r.name == "env:KRYON_MODEL")
    assert env.ok is True
