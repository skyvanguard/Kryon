"""F132 — Per-target engagement state tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from kryon.state.engagement_state import (
    EngagementState,
    minutes_since,
    read_state,
    target_slug,
    write_state,
)

# ---------------------------------------------------------------------------
# target_slug
# ---------------------------------------------------------------------------


def test_slug_strips_scheme():
    assert target_slug("https://www.example.com") == "www.example.com"


def test_slug_handles_port_and_path():
    assert target_slug("https://www.example.com:443/admin") == "www.example.com_443_admin"


def test_slug_handles_ip_with_cidr():
    assert target_slug("10.0.0.0/24") == "10.0.0.0_24"


def test_slug_lowercases():
    assert target_slug("WWW.EXAMPLE.COM") == "www.example.com"


def test_slug_empty_target_returns_fallback():
    assert target_slug("") == "target"
    assert target_slug(None) == "target"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# read_state + write_state
# ---------------------------------------------------------------------------


def test_read_state_missing_returns_none(tmp_path):
    state = read_state("nonexistent.com", state_dir=tmp_path)
    assert state is None


def test_write_state_creates_file(tmp_path):
    written = write_state(
        "x.com",
        engagement_id="eng-1",
        findings_path="/tmp/findings.json",
        finding_count=5,
        state_dir=tmp_path,
    )
    assert written is not None
    p = tmp_path / "x.com.json"
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["target"] == "x.com"
    assert data["last_engagement_id"] == "eng-1"
    assert data["finding_count"] == 5


def test_write_then_read_roundtrip(tmp_path):
    write_state(
        "x.com",
        engagement_id="eng-1",
        findings_path="/tmp/findings.json",
        finding_count=5,
        state_dir=tmp_path,
    )
    state = read_state("x.com", state_dir=tmp_path)
    assert state is not None
    assert state.last_engagement_id == "eng-1"
    assert state.finding_count == 5


def test_write_state_overwrites_previous(tmp_path):
    write_state("x.com", engagement_id="eng-1", findings_path="a", finding_count=1, state_dir=tmp_path)
    write_state("x.com", engagement_id="eng-2", findings_path="b", finding_count=10, state_dir=tmp_path)
    state = read_state("x.com", state_dir=tmp_path)
    assert state is not None
    assert state.last_engagement_id == "eng-2"
    assert state.finding_count == 10


def test_read_state_malformed_returns_none(tmp_path):
    p = tmp_path / "broken.com.json"
    p.write_text("not json", encoding="utf-8")
    state = read_state("broken.com", state_dir=tmp_path)
    assert state is None


def test_write_state_creates_parent_dir(tmp_path):
    nested = tmp_path / "deep" / "nested"
    write_state(
        "x.com",
        engagement_id="e",
        findings_path="p",
        finding_count=0,
        state_dir=nested,
    )
    assert (nested / "x.com.json").exists()


# ---------------------------------------------------------------------------
# minutes_since
# ---------------------------------------------------------------------------


def test_minutes_since_recent_state(tmp_path):
    # Write a state with a recent timestamp.
    write_state("x.com", engagement_id="e", findings_path="p", finding_count=0, state_dir=tmp_path)
    state = read_state("x.com", state_dir=tmp_path)
    assert state is not None
    elapsed = minutes_since(state)
    assert elapsed is not None
    assert elapsed < 1.0  # written less than a second ago


def test_minutes_since_old_timestamp():
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds").replace("+00:00", "Z")
    state = EngagementState(target="x", last_engagement_id="e", last_run_ts=old, findings_path="p", finding_count=0)
    elapsed = minutes_since(state)
    assert elapsed is not None
    assert 119 < elapsed < 121  # ~2 hours = ~120 min


def test_minutes_since_invalid_timestamp_returns_none():
    state = EngagementState(
        target="x", last_engagement_id="e", last_run_ts="not-a-date", findings_path="p", finding_count=0
    )
    assert minutes_since(state) is None


def test_minutes_since_none_state_returns_none():
    assert minutes_since(None) is None  # type: ignore[arg-type]
