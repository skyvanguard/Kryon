"""SIEM event models for normalized security event forwarding."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class SIEMEvent(BaseModel):
    """Normalized security event for SIEM forwarding."""

    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str  # 'finding' | 'scan_start' | 'scan_complete' | 'auth' | 'audit'
    severity: str = "info"  # 'critical' | 'high' | 'medium' | 'low' | 'info'
    source: str = "kryon"
    title: str = ""
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    client_id: str | None = None
    user: str | None = None


class SIEMConfig(BaseModel):
    """Configuration for a SIEM integration."""

    id: str
    name: str
    siem_type: str  # 'splunk' | 'qradar' | 'elastic'
    endpoint: str
    token: str = ""
    index_name: str = ""
    enabled: bool = True
    config_json: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str | None = None
