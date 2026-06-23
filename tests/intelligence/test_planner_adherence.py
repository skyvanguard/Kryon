"""Tests for planner-adherence telemetry (Tier 2 scaffolding maturity)."""

from __future__ import annotations

from kryon.intelligence.planner_adherence import AdherenceTracker, adheres


def test_adheres_exact_and_delegation():
    assert adheres("run_command", "run_command")
    assert adheres("run_command", "run_command_async")  # canonicalized
    assert adheres("GetNPUsers.py", "execute_planner_directive")  # delegation = followed
    assert not adheres("GetNPUsers.py", "web_fetch_smart")  # different tool = ignored


def test_tracker_counts_followed_and_ignored():
    t = AdherenceTracker()
    t.record_injection(turn=1, tool="GetNPUsers.py", confidence=0.92)
    t.record_action(tool="GetNPUsers.py")  # followed
    t.record_injection(turn=2, tool="secretsdump.py", confidence=0.92)
    t.record_action(tool="run_command")  # ignored (model improvised)
    assert t.total_injected == 2
    assert t.total_followed == 1
    assert t.adherence_rate() == 0.5


def test_unacted_injection_resolves_as_ignored():
    t = AdherenceTracker()
    t.record_injection(turn=1, tool="x", confidence=0.92)
    # A second injection lands before the model acted on the first → first is 'not followed'.
    t.record_injection(turn=2, tool="y", confidence=0.92)
    t.record_action(tool="y")
    assert t.total_injected == 2
    assert t.total_followed == 1  # only the 2nd was followed
    assert len(t.records) == 2
    assert t.records[0]["followed"] is False
    assert t.records[0]["actual"] == "(none)"


def test_flush_gated_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("KRYON_PLANNER_TELEMETRY", raising=False)
    monkeypatch.setenv("KRYON_PLANNER_TELEMETRY_PATH", str(tmp_path / "adh.jsonl"))
    t = AdherenceTracker()
    t.record_injection(turn=1, tool="x", confidence=0.92)
    t.record_action(tool="x")
    t.flush(run_id="r1")
    assert not (tmp_path / "adh.jsonl").exists()  # disabled → no write


def test_flush_writes_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_PLANNER_TELEMETRY", "true")
    monkeypatch.setenv("KRYON_PLANNER_TELEMETRY_PATH", str(tmp_path / "adh.jsonl"))
    t = AdherenceTracker()
    t.record_injection(turn=1, tool="x", confidence=0.92)
    t.record_action(tool="x")
    t.flush(run_id="r1", target="10.0.0.1")
    lines = (tmp_path / "adh.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert '"followed": true' in lines[0]
    assert '"run_id": "r1"' in lines[0]
