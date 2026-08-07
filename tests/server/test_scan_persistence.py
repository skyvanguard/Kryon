"""Tests for auto-scan persistence — the linchpin that makes the dashboard
show data after a scan (findings/drift/KPIs all read from the store).

Exercises ``_persist_auto_scan`` directly with a fake orchestrator + a real
seeded MemoryStore, then confirms the persisted data is visible through the
findings and drift endpoints.
"""

from __future__ import annotations

import pytest

from kryon.intelligence.models import Finding, Severity
from kryon.memory.store import MemoryStore
from kryon.server.routes import findings as findings_mod, scans as scans_mod


class _FakeProgress:
    scan_id = "auto-123"


class _FakeOrch:
    def __init__(self, findings):
        self.findings = findings
        self.progress = _FakeProgress()


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = MemoryStore(db_path=tmp_path / "persist.db")
    monkeypatch.setattr(scans_mod, "get_store", lambda: s)
    monkeypatch.setattr(findings_mod, "get_store", lambda: s)
    return s


def _finding(title, asset, sev):
    return Finding(title=title, description=f"{title} detail", severity=sev, affected_asset=asset)


def test_persist_creates_scan_and_findings(store):
    orch = _FakeOrch(
        [
            _finding("SSH password auth", "10.0.0.1", Severity.HIGH),
            _finding("TLS 1.0 enabled", "10.0.0.2", Severity.MEDIUM),
        ]
    )
    scans_mod._persist_auto_scan(orch, "acme")

    scans = store.list_scans(client_id="acme")
    assert len(scans) == 1
    assert scans[0].finding_count == 2
    persisted = store.get_findings(scans[0].id)
    assert len(persisted) == 2


def test_persist_autocreates_missing_client(store):
    """create_scan has a FK to clients — persistence must create the client."""
    orch = _FakeOrch([_finding("Open port", "10.0.0.9", Severity.LOW)])
    scans_mod._persist_auto_scan(orch, "brand-new-client")

    assert store.get_client("brand-new-client") is not None
    assert len(store.list_scans(client_id="brand-new-client")) == 1


def test_persist_empty_client_id_uses_default(store):
    orch = _FakeOrch([_finding("Finding", "h", Severity.INFO)])
    scans_mod._persist_auto_scan(orch, "")

    assert store.get_client("default") is not None
    assert len(store.list_scans(client_id="default")) == 1


async def test_persisted_findings_feed_the_drift_endpoint(store):
    """Two persisted scans should produce a real drift diff."""
    scans_mod._persist_auto_scan(_FakeOrch([_finding("A", "h1", Severity.LOW)]), "acme")
    scans_mod._persist_auto_scan(
        _FakeOrch([_finding("A", "h1", Severity.HIGH), _finding("B", "h2", Severity.MEDIUM)]),
        "acme",
    )

    result = await findings_mod.findings_drift(client_id="acme", user=None)

    assert result["baseline"] is True
    # A bumped LOW->HIGH (changed), B is new.
    assert result["summary"]["new"] == 1
    assert result["summary"]["changed"] == 1
