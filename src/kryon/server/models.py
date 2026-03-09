"""Pydantic request/response schemas for the API."""

from __future__ import annotations

from typing import Any, Literal, Optional

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


# --- Client Management ---


class ClientCreate(BaseModel):
    name: str
    scope: list[str] = []
    contact: str = ""
    notes: str = ""
    tags: list[str] = []


class ClientUpdate(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    contact: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


# --- Scheduled Scans ---


class ScheduleScanRequest(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=100)
    agent_key: str = Field("pentest_agent", min_length=1, max_length=100)
    profile: str = Field("standard", max_length=50)
    interval_seconds: int = Field(604800, ge=60, le=2592000)  # 1min–30days
    cron: str = Field("", max_length=100)
    webhook_url: str | None = Field(None, max_length=2000)


# --- Knowledge Base ---


class KnowledgeQueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    top_k: int = Field(5, ge=1, le=50)
    source_filter: str | None = None
    use_llm: bool = False


class KnowledgeQueryResponse(BaseModel):
    question: str
    answer: str | None = None
    sources: list[dict] = []
    num_sources: int = 0


class KnowledgeAddRequest(BaseModel):
    content: str = Field(..., max_length=500_000)
    source: str = Field(..., min_length=1, max_length=500)
    metadata: dict | None = None


class KnowledgeAddResponse(BaseModel):
    doc_id: str
    success: bool


class KnowledgeStatsResponse(BaseModel):
    total_documents: int = 0
    sources: dict = {}
    llm_configured: bool = False
    llm_model: str = "unknown"


class ScrapeRequest(BaseModel):
    sources: list[str] = Field(default=["intelligence", "nvd"], max_length=20)
    nvd_days: int = Field(30, ge=1, le=365)
    nvd_count: int = Field(200, ge=1, le=5000)


class ScrapeResponse(BaseModel):
    task_id: str
    status: str
    message: str


# --- AppSec ---


class SASTScanRequest(BaseModel):
    target_path: str = Field(..., max_length=500, description="Path to source code")
    config: str = Field("auto", description="Semgrep config (auto, p/security-audit, etc.)")
    severity: str = Field("ERROR,WARNING", description="Severity filter")
    language: str = Field("", description="Limit to specific language")


class DASTScanRequest(BaseModel):
    target_url: str = Field(..., max_length=2000, description="Target URL")
    minutes: int = Field(5, ge=1, le=120, description="Scan duration")
    ajax_spider: bool = Field(False, description="Enable Ajax spider")


class SBOMRequest(BaseModel):
    target: str = Field(..., max_length=500, description="Target to analyze")
    format: str = Field("cyclonedx-json", description="SBOM format")
    source_type: str = Field("dir", description="Source type (dir, image)")


# --- Validation ---


class SimulateRequest(BaseModel):
    technique_id: str = Field(..., max_length=20, description="MITRE ATT&CK technique ID")
    target: str = Field(..., max_length=500, description="Target host/IP")
    mode: str = Field("safe", description="Execution mode (safe, full)")


class DetectRequest(BaseModel):
    technique_id: str = Field(..., max_length=20, description="Technique to validate")
    siem_type: Literal["elastic", "splunk"] = Field("elastic", description="SIEM platform")
    siem_endpoint: str = Field("", max_length=500, description="SIEM API endpoint")
    time_window_minutes: int = Field(15, ge=1, le=1440)


# --- Compliance ---


class ComplianceAssessRequest(BaseModel):
    framework: str = Field(..., description="Framework ID (pci_dss, soc2, nist_csf, etc.)")
    client_id: str = Field("", description="Client ID to scope findings")
