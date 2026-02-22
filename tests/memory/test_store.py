"""Tests for MemoryStore SQLite operations."""

import pytest

from kryon.memory.models import (
    AgentExperience,
    Client,
    FindingRecord,
    ScanRecord,
)
from kryon.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path):
    s = MemoryStore(db_path=tmp_path / "test.db")
    yield s
    s.close()


# --- Client CRUD ---

def test_create_and_get_client(store):
    client = Client(name="Test Corp", scope=["192.168.1.0/24"], tags=["pyme"])
    store.create_client(client)
    retrieved = store.get_client(client.id)
    assert retrieved is not None
    assert retrieved.name == "Test Corp"
    assert retrieved.scope == ["192.168.1.0/24"]
    assert retrieved.tags == ["pyme"]


def test_list_clients(store):
    store.create_client(Client(name="A"))
    store.create_client(Client(name="B"))
    clients = store.list_clients()
    assert len(clients) == 2


def test_update_client(store):
    client = Client(name="Old Name")
    store.create_client(client)
    updated = store.update_client(client.id, name="New Name")
    assert updated.name == "New Name"


def test_delete_client(store):
    client = Client(name="To Delete")
    store.create_client(client)
    assert store.delete_client(client.id) is True
    assert store.get_client(client.id) is None


def test_get_nonexistent_client(store):
    assert store.get_client("nonexistent") is None


# --- Scan Records ---

def test_create_and_get_scan(store):
    client = Client(name="C")
    store.create_client(client)
    scan = ScanRecord(client_id=client.id, agent_key="pentest_agent")
    store.create_scan(scan)
    retrieved = store.get_scan(scan.id)
    assert retrieved is not None
    assert retrieved.client_id == client.id
    assert retrieved.status == "running"


def test_list_scans_by_client(store):
    c1 = Client(name="C1")
    c2 = Client(name="C2")
    store.create_client(c1)
    store.create_client(c2)
    store.create_scan(ScanRecord(client_id=c1.id))
    store.create_scan(ScanRecord(client_id=c1.id))
    store.create_scan(ScanRecord(client_id=c2.id))
    assert len(store.list_scans(c1.id)) == 2
    assert len(store.list_scans(c2.id)) == 1


def test_update_scan(store):
    client = Client(name="C")
    store.create_client(client)
    scan = ScanRecord(client_id=client.id)
    store.create_scan(scan)
    updated = store.update_scan(scan.id, status="completed", finding_count=5)
    assert updated.status == "completed"
    assert updated.finding_count == 5


# --- Findings ---

def test_save_and_get_findings(store):
    client = Client(name="C")
    store.create_client(client)
    scan = ScanRecord(client_id=client.id)
    store.create_scan(scan)
    f1 = FindingRecord(scan_id=scan.id, client_id=client.id, finding_json='{"title":"SQLi"}')
    f2 = FindingRecord(scan_id=scan.id, client_id=client.id, finding_json='{"title":"XSS"}')
    store.save_finding(f1)
    store.save_finding(f2)
    findings = store.get_findings(scan.id)
    assert len(findings) == 2


def test_get_client_findings_by_status(store):
    client = Client(name="C")
    store.create_client(client)
    scan = ScanRecord(client_id=client.id)
    store.create_scan(scan)
    f1 = FindingRecord(scan_id=scan.id, client_id=client.id, status="open")
    f2 = FindingRecord(scan_id=scan.id, client_id=client.id, status="remediated")
    store.save_finding(f1)
    store.save_finding(f2)
    open_f = store.get_client_findings(client.id, status="open")
    assert len(open_f) == 1


def test_update_finding_status(store):
    client = Client(name="C")
    store.create_client(client)
    scan = ScanRecord(client_id=client.id)
    store.create_scan(scan)
    f = FindingRecord(scan_id=scan.id, client_id=client.id, status="open")
    store.save_finding(f)
    assert store.update_finding_status(f.id, "remediated") is True
    findings = store.get_client_findings(client.id, status="remediated")
    assert len(findings) == 1


# --- Agent Experience ---

def test_save_and_get_experience(store):
    exp = AgentExperience(
        agent_key="pentest_agent",
        target_type="wordpress",
        strategy="Start with wpscan, then nuclei",
        tools_effective=["wpscan", "nuclei"],
        tools_ineffective=["nikto"],
    )
    store.save_experience(exp)
    results = store.get_experience("pentest_agent", "wordpress")
    assert len(results) == 1
    assert results[0].tools_effective == ["wpscan", "nuclei"]


def test_cascade_delete(store):
    """Deleting a client should delete its scans and findings."""
    client = Client(name="C")
    store.create_client(client)
    scan = ScanRecord(client_id=client.id)
    store.create_scan(scan)
    store.save_finding(FindingRecord(scan_id=scan.id, client_id=client.id))
    store.delete_client(client.id)
    assert store.list_scans(client.id) == []
    assert store.get_client_findings(client.id) == []
