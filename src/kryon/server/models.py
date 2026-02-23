"""Pydantic request/response schemas for the API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

# --- Requests ---


class RunRequest(BaseModel):
    agent_key: str = Field(..., description="Agent key (e.g. 'recon_scout')")
    input: str = Field(..., description="User prompt")
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


class AgentSummary(BaseModel):
    key: str
    name: str
    description: str | None = None


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


class ErrorResponse(BaseModel):
    detail: str
