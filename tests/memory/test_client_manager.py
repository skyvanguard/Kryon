"""Tests for ClientManager."""

import pytest

from kryon.memory.client_manager import ClientManager
from kryon.memory.models import Client, FindingRecord, ScanRecord
from kryon.memory.store import MemoryStore


@pytest.fixture
def manager(tmp_path):
    store = MemoryStore(db_path=tmp_path / "test.db")
    mgr = ClientManager(store)
    yield mgr
    store.close()


def test_client_progress_no_scans(manager):
    client = Client(name="C")
    manager.store.create_client(client)
    progress = manager.get_client_progress(client.id)
    assert progress["scans"] == 0
    assert progress["trend"] == "no_data"


def test_client_progress_improving(manager):
    client = Client(name="C")
    manager.store.create_client(client)
    # First scan: high risk (older timestamp)
    s1 = ScanRecord(
        client_id=client.id,
        risk_score=80.0,
        finding_count=10,
        status="completed",
        started_at="2026-01-01T00:00:00Z",
    )
    manager.store.create_scan(s1)
    # Second scan: lower risk (newer timestamp)
    s2 = ScanRecord(
        client_id=client.id,
        risk_score=40.0,
        finding_count=5,
        status="completed",
        started_at="2026-01-02T00:00:00Z",
    )
    manager.store.create_scan(s2)

    progress = manager.get_client_progress(client.id)
    assert progress["scans"] == 2
    assert progress["trend"] == "improving"
    assert progress["risk_delta"] == -40.0


def test_client_timeline(manager):
    client = Client(name="C")
    manager.store.create_client(client)
    manager.store.create_scan(ScanRecord(client_id=client.id, agent_key="recon_scout"))
    manager.store.create_scan(ScanRecord(client_id=client.id, agent_key="vuln_hunter"))

    timeline = manager.get_client_timeline(client.id)
    assert len(timeline) == 2


def test_remediation_rate(manager):
    client = Client(name="C")
    manager.store.create_client(client)
    scan = ScanRecord(client_id=client.id)
    manager.store.create_scan(scan)
    # 3 findings: 1 remediated, 2 open
    manager.store.save_finding(FindingRecord(scan_id=scan.id, client_id=client.id, status="open"))
    manager.store.save_finding(FindingRecord(scan_id=scan.id, client_id=client.id, status="open"))
    manager.store.save_finding(FindingRecord(scan_id=scan.id, client_id=client.id, status="remediated"))

    rate = manager.get_remediation_rate(client.id)
    assert rate == pytest.approx(33.3, abs=0.1)


def test_remediation_rate_empty(manager):
    client = Client(name="C")
    manager.store.create_client(client)
    assert manager.get_remediation_rate(client.id) == 0.0
