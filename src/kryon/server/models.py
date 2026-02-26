"""Pydantic request/response schemas for the API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

# --- Requests ---


class RunRequest(BaseModel):
    agent_key: str = Field(..., description="Agent key (e.g. 'recon_scout')")
    input: str = Field(..., max_length=50000, description="User prompt")
    session_id: Optional[str] = Field(None, description="Session ID to continue conversation")
    stream: bool = Field(False, description="Stream response via SSE")
    max_turns: int = Field(10, ge=1, le=100, description="Max agent turns")


class SessionCreateRequest(BaseModel):
    agent_key: str = Field(..., description="Agent key for the session")


# --- Responses ---


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    agents_count: int


class ReadinessCheck(BaseModel):
    status: str
    error: str | None = None


class ReadinessResponse(BaseModel):
    status: str = "ok"
    version: str
    uptime_seconds: float = 0.0
    checks: dict[str, ReadinessCheck] = Field(default_factory=dict)


class AgentSummary(BaseModel):
    key: str
    name: str
    description: str | None = None
    category: str = "agent"


class AgentDetail(AgentSummary):
    tools: list[str] = Field(default_factory=list)
    handoffs: list[str] = Field(default_factory=list)
    model: str | None = None
    has_guardrails: bool = False


class RunResponse(BaseModel):
    run_id: str
    status: str = "completed"
    output: str = ""
    agent: str = ""
    usage: dict[str, Any] = Field(default_factory=dict)


class RunStatus(BaseModel):
    run_id: str
    status: str
    agent: str | None = None
    output: str | None = None


class SessionResponse(BaseModel):
    session_id: str
    agent_key: str
    created_at: str
    message_count: int = 0


class UsageSummary(BaseModel):
    global_totals: dict[str, Any] = Field(default_factory=dict)
    top_models: list[list[Any]] = Field(default_factory=list)
    recent_sessions: list[dict[str, Any]] = Field(default_factory=list)


class ModelUsage(BaseModel):
    model: str
    total_cost: float
    total_input_tokens: int
    total_output_tokens: int
    total_requests: int


class DailyUsage(BaseModel):
    date: str
    total_cost: float
    total_input_tokens: int
    total_output_tokens: int
    total_requests: int


# --- Auto-Scan ---


class AutoScanRequest(BaseModel):
    targets: list[str] = Field(..., max_length=100, description="List of targets (IPs, CIDRs, hostnames)")
    profile: str = Field("standard", description="Scan profile name")
    client_id: str = Field("", description="Client ID or name")
    max_time_hours: float = Field(4.0, ge=0.1, le=24.0, description="Max scan duration in hours")
    stealth_level: str = Field("normal", description="Stealth level: low, normal, high")
    output_format: str = Field("html", description="Report format: html, pdf, json")
    compliance_frameworks: list[str] = Field(default_factory=list, description="Compliance frameworks")


class AutoScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str = ""


class AutoScanStatus(BaseModel):
    scan_id: str
    status: str
    phase_progress: float = 0.0
    hosts_discovered: int = 0
    hosts_scanned: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    elapsed_seconds: float = 0.0
    log_messages: list[str] = Field(default_factory=list)
    report_path: Optional[str] = None
    error: Optional[str] = None


class AutoScanFinding(BaseModel):
    id: str
    title: str
    severity: str
    affected_asset: str
    description: str = ""
    cvss_score: Optional[float] = None
    tool_source: str = ""
    remediation: str = ""


# --- Engagements ---


class CreateEngagementRequest(BaseModel):
    client_name: str = Field(..., max_length=200, description="Client/organization name")
    targets: list[str] = Field(..., max_length=50, description="List of targets (IPs, CIDRs, domains)")
    objectives: list[str] = Field(
        default=["initial_access", "vulnerability_assessment", "exploitation"],
        description="Engagement objectives",
    )
    duration_days: int = Field(5, ge=1, le=30, description="Planned duration in days")
    stealth_level: str = Field("normal", description="Stealth level: low, normal, high")
    phase_interval_minutes: int = Field(30, ge=0, le=1440, description="Wait time between phases in minutes")


class EngagementResponse(BaseModel):
    id: str
    status: str
    message: str = ""


class ErrorResponse(BaseModel):
    detail: str
