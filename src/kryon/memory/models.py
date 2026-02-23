"""Memory data models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Client(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str
    scope: list[str] = []
    contact: str = ""
    notes: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = []


class ScanRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    client_id: str
    agent_key: str = ""
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    status: str = "running"  # running, completed, failed
    finding_count: int = 0
    risk_score: float = 0.0
    report_id: str | None = None


class FindingRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    scan_id: str
    client_id: str
    finding_json: str = ""  # JSON-serialized Finding from intelligence.models
    status: str = "open"  # open, remediated, accepted, false_positive
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    occurrences: int = 1


class AgentExperience(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_key: str
    target_type: str = ""
    strategy: str = ""
    tools_effective: list[str] = []
    tools_ineffective: list[str] = []
    notes: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
