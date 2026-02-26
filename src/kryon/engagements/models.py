"""Engagement data models for multi-day autonomous pentesting."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class EngagementStatus(str, Enum):
    CREATED = "created"
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PhaseType(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    DEEP_EXPLOITATION = "deep_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE_TESTING = "persistence_testing"
    REPORTING = "reporting"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# Map phase types to the agent that executes them
PHASE_AGENT_MAP: dict[str, str] = {
    PhaseType.RECONNAISSANCE: "recon_scout",
    PhaseType.VULNERABILITY_ASSESSMENT: "vuln_hunter",
    PhaseType.EXPLOITATION: "pentest_agent",
    PhaseType.DEEP_EXPLOITATION: "pentest_agent",
    PhaseType.LATERAL_MOVEMENT: "network_analyst",
    PhaseType.PERSISTENCE_TESTING: "pentest_agent",
    PhaseType.REPORTING: "reporter",
}


class Engagement(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    client_name: str
    targets: list[str] = Field(default_factory=list)
    objectives: list[str] = Field(
        default_factory=lambda: ["initial_access", "vulnerability_assessment", "exploitation"]
    )
    duration_days: int = 5
    status: EngagementStatus = EngagementStatus.CREATED
    plan_json: str = ""
    current_phase_id: str | None = None
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    risk_score: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    paused_at: str | None = None
    error: str | None = None
    stealth_level: str = "normal"
    profile: str = "enterprise_deep"
    phase_interval_minutes: int = 30


class EngagementPhase(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    phase_type: PhaseType
    day_number: int = 1
    order_index: int = 0
    status: PhaseStatus = PhaseStatus.PENDING
    agent_key: str = ""
    scan_id: str | None = None
    targets_subset: str = "[]"
    config_json: str = "{}"
    findings_count: int = 0
    progress: float = 0.0
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    checkpoint_json: str = "{}"
    log_messages: str = "[]"
