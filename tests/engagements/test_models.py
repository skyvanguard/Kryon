"""Tests for engagement data models."""

from kryon.engagements.models import (
    PHASE_AGENT_MAP,
    Engagement,
    EngagementPhase,
    EngagementStatus,
    PhaseStatus,
    PhaseType,
)


def test_engagement_defaults():
    e = Engagement(client_name="TestCorp", targets=["10.0.0.0/24"])
    assert e.client_name == "TestCorp"
    assert e.targets == ["10.0.0.0/24"]
    assert e.status == EngagementStatus.CREATED
    assert e.duration_days == 5
    assert e.phase_interval_minutes == 30
    assert e.total_findings == 0
    assert e.id  # auto-generated


def test_engagement_status_enum():
    assert EngagementStatus.CREATED.value == "created"
    assert EngagementStatus.ACTIVE.value == "active"
    assert EngagementStatus.PAUSED.value == "paused"
    assert EngagementStatus.COMPLETED.value == "completed"
    assert EngagementStatus.FAILED.value == "failed"
    assert EngagementStatus.CANCELLED.value == "cancelled"


def test_phase_types():
    assert PhaseType.RECONNAISSANCE.value == "reconnaissance"
    assert PhaseType.REPORTING.value == "reporting"
    assert len(PhaseType) == 7


def test_phase_status():
    assert PhaseStatus.PENDING.value == "pending"
    assert PhaseStatus.RUNNING.value == "running"
    assert PhaseStatus.COMPLETED.value == "completed"


def test_phase_agent_map():
    assert PHASE_AGENT_MAP[PhaseType.RECONNAISSANCE] == "recon_scout"
    assert PHASE_AGENT_MAP[PhaseType.VULNERABILITY_ASSESSMENT] == "vuln_hunter"
    assert PHASE_AGENT_MAP[PhaseType.EXPLOITATION] == "pentest_agent"
    assert PHASE_AGENT_MAP[PhaseType.REPORTING] == "reporter"


def test_engagement_phase_defaults():
    p = EngagementPhase(
        engagement_id="abc123",
        phase_type=PhaseType.RECONNAISSANCE,
        agent_key="recon_scout",
    )
    assert p.engagement_id == "abc123"
    assert p.phase_type == PhaseType.RECONNAISSANCE
    assert p.status == PhaseStatus.PENDING
    assert p.progress == 0.0
    assert p.day_number == 1


def test_engagement_serialization():
    e = Engagement(client_name="Test", targets=["1.2.3.4"])
    data = e.model_dump()
    assert data["client_name"] == "Test"
    assert data["targets"] == ["1.2.3.4"]
    assert data["status"] == EngagementStatus.CREATED

    # Roundtrip
    e2 = Engagement(**data)
    assert e2.id == e.id
    assert e2.client_name == e.client_name
