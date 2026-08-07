"""Tests for the /findings/drift endpoint — baseline drift between the two
most recent scans of a client.

Exercises the endpoint function directly against a seeded MemoryStore (fast,
deterministic, avoids the TestClient lifespan path). Verifies the store →
_load_scan_findings → compute_diff wiring produces the right buckets.
"""

from __future__ import annotations

import json

import pytest

from kryon.memory.models import Client, FindingRecord, ScanRecord
from kryon.memory.store import MemoryStore
from kryon.server.routes import findings as findings_mod


@pytest.fixture
def seeded_store(tmp_path, monkeypatch):
    """A MemoryStore wired into the findings route via monkeypatch."""
    store = MemoryStore(db_path=tmp_path / "drift.db")
    store.create_client(Client(id="c1", name="Cliente Uno"))
    monkeypatch.setattr(findings_mod, "get_store", lambda: store)
    return store


def _finding_json(title: str, asset: str, severity: str, evidence: str = "") -> str:
    return json.dumps({"title": title, "affected_asset": asset, "severity": severity, "evidence": evidence})


def _seed_scan(store: MemoryStore, scan_id: str, started_at: str, findings: list[tuple]) -> None:
    store.create_scan(ScanRecord(id=scan_id, client_id="c1", started_at=started_at, status="completed"))
    for title, asset, sev in findings:
        store.save_finding(
            FindingRecord(scan_id=scan_id, client_id="c1", finding_json=_finding_json(title, asset, sev))
        )


async def test_drift_warmup_with_single_scan(seeded_store):
    """A client with fewer than two scans has no baseline to compare."""
    _seed_scan(seeded_store, "s1", "2026-07-20T10:00:00+00:00", [("SSH weak", "10.0.0.1", "LOW")])

    result = await findings_mod.findings_drift(client_id="c1", user=None)

    assert result["baseline"] is False
    assert result["summary"] == {"new": 0, "gone": 0, "changed": 0, "stable": 0}


async def test_drift_detects_new_gone_and_changed(seeded_store):
    """Two scans: one new finding, one remediated, one severity-bumped."""
    # Older scan (baseline): A=LOW, B=HIGH
    _seed_scan(
        seeded_store,
        "prev",
        "2026-07-20T10:00:00+00:00",
        [("SSH password auth", "10.0.0.1", "LOW"), ("RDP 3389 exposed", "10.0.0.2", "HIGH")],
    )
    # Newer scan (current): A=HIGH (changed), C=MEDIUM (new); B gone (remediated)
    _seed_scan(
        seeded_store,
        "curr",
        "2026-07-27T10:00:00+00:00",
        [("SSH password auth", "10.0.0.1", "HIGH"), ("TLS 1.0 enabled", "10.0.0.3", "MEDIUM")],
    )

    result = await findings_mod.findings_drift(client_id="c1", user=None)

    assert result["baseline"] is True
    assert result["summary"] == {"new": 1, "gone": 1, "changed": 1, "stable": 0}
    assert result["current_scan"] == "2026-07-27T10:00:00+00:00"
    assert result["previous_scan"] == "2026-07-20T10:00:00+00:00"
    assert [f["title"] for f in result["new"]] == ["TLS 1.0 enabled"]
    assert [f["title"] for f in result["gone"]] == ["RDP 3389 exposed"]
    changed = result["changed"][0]
    assert changed["previous"]["severity"] == "LOW"
    assert changed["current"]["severity"] == "HIGH"


async def test_drift_stable_when_nothing_changes(seeded_store):
    """Identical findings across two scans register as stable, not drift."""
    same = [("SSH password auth", "10.0.0.1", "LOW")]
    _seed_scan(seeded_store, "prev", "2026-07-20T10:00:00+00:00", same)
    _seed_scan(seeded_store, "curr", "2026-07-27T10:00:00+00:00", same)

    result = await findings_mod.findings_drift(client_id="c1", user=None)

    assert result["summary"] == {"new": 0, "gone": 0, "changed": 0, "stable": 1}
