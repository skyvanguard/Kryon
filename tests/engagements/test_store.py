"""Tests for engagement persistence in MemoryStore."""

import tempfile
from pathlib import Path

import pytest

from kryon.engagements.models import (
    Engagement,
    EngagementPhase,
    EngagementStatus,
    PhaseStatus,
    PhaseType,
)
from kryon.memory.store import MemoryStore


@pytest.fixture
def store():
    """Create a temporary MemoryStore for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    s = MemoryStore(db_path=db_path)
    yield s
    s.close()
    db_path.unlink(missing_ok=True)


@pytest.fixture
def sample_engagement():
    return Engagement(
        client_name="TestCorp",
        targets=["192.168.1.0/24", "10.0.0.1"],
        objectives=["initial_access", "exploitation"],
        duration_days=3,
    )


class TestEngagementCRUD:
    def test_create_and_get(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        loaded = store.get_engagement(sample_engagement.id)
        assert loaded is not None
        assert loaded.client_name == "TestCorp"
        assert loaded.targets == ["192.168.1.0/24", "10.0.0.1"]
        assert loaded.status == EngagementStatus.CREATED

    def test_get_nonexistent(self, store):
        assert store.get_engagement("nonexistent") is None

    def test_list_all(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        e2 = Engagement(client_name="OtherCorp", targets=["10.0.0.0/8"])
        store.create_engagement(e2)
        all_eng = store.list_engagements()
        assert len(all_eng) == 2

    def test_list_by_status(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        store.update_engagement(sample_engagement.id, status="active")

        e2 = Engagement(client_name="Other", targets=["10.0.0.1"])
        store.create_engagement(e2)

        active = store.list_engagements(status_filter=["active"])
        assert len(active) == 1
        assert active[0].client_name == "TestCorp"

        created = store.list_engagements(status_filter=["created"])
        assert len(created) == 1

    def test_update(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        store.update_engagement(
            sample_engagement.id,
            status="active",
            total_findings=10,
            critical_findings=2,
        )
        updated = store.get_engagement(sample_engagement.id)
        assert updated.status == EngagementStatus.ACTIVE
        assert updated.total_findings == 10
        assert updated.critical_findings == 2

    def test_delete(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        assert store.delete_engagement(sample_engagement.id) is True
        assert store.get_engagement(sample_engagement.id) is None

    def test_delete_nonexistent(self, store):
        assert store.delete_engagement("nonexistent") is False

    def test_delete_cascades_phases(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        phase = EngagementPhase(
            engagement_id=sample_engagement.id,
            phase_type=PhaseType.RECONNAISSANCE,
            agent_key="recon_scout",
        )
        store.create_engagement_phase(phase)
        assert len(store.get_engagement_phases(sample_engagement.id)) == 1

        store.delete_engagement(sample_engagement.id)
        assert len(store.get_engagement_phases(sample_engagement.id)) == 0


class TestEngagementPhaseCRUD:
    def test_create_and_get(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        phase = EngagementPhase(
            engagement_id=sample_engagement.id,
            phase_type=PhaseType.RECONNAISSANCE,
            agent_key="recon_scout",
            day_number=1,
        )
        store.create_engagement_phase(phase)

        phases = store.get_engagement_phases(sample_engagement.id)
        assert len(phases) == 1
        assert phases[0].phase_type == PhaseType.RECONNAISSANCE
        assert phases[0].agent_key == "recon_scout"

    def test_multiple_phases_ordered(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        for i, pt in enumerate([PhaseType.RECONNAISSANCE, PhaseType.EXPLOITATION, PhaseType.REPORTING]):
            phase = EngagementPhase(
                engagement_id=sample_engagement.id,
                phase_type=pt,
                agent_key="agent",
                day_number=i + 1,
                order_index=0,
            )
            store.create_engagement_phase(phase)

        phases = store.get_engagement_phases(sample_engagement.id)
        assert len(phases) == 3
        assert phases[0].day_number == 1
        assert phases[1].day_number == 2
        assert phases[2].day_number == 3

    def test_update_phase(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        phase = EngagementPhase(
            engagement_id=sample_engagement.id,
            phase_type=PhaseType.EXPLOITATION,
            agent_key="pentest_agent",
        )
        store.create_engagement_phase(phase)

        store.update_engagement_phase(phase.id, status="running", progress=0.5)
        updated = store.get_engagement_phase(phase.id)
        assert updated.status == PhaseStatus.RUNNING
        assert updated.progress == 0.5

    def test_get_single_phase(self, store, sample_engagement):
        store.create_engagement(sample_engagement)
        phase = EngagementPhase(
            engagement_id=sample_engagement.id,
            phase_type=PhaseType.REPORTING,
            agent_key="reporter",
        )
        store.create_engagement_phase(phase)

        loaded = store.get_engagement_phase(phase.id)
        assert loaded is not None
        assert loaded.phase_type == PhaseType.REPORTING

    def test_get_nonexistent_phase(self, store):
        assert store.get_engagement_phase("nonexistent") is None
