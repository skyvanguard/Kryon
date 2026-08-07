"""Reporting data models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from kryon.intelligence.models import Finding


class ReportType(str, Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"


class ReportConfig(BaseModel):
    report_type: ReportType = ReportType.TECHNICAL
    client_name: str = ""
    target_scope: str = ""
    date: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    include_evidence: bool = True
    include_mitre: bool = True
    include_compliance: list[str] = []
    format: str = "html"  # html | pdf
    logo_path: str | None = None
    # F85.H — Cover page + branding fields. ``client_logo_path`` paints
    # the cover; ``client_color`` recolors the CSS theme; ``classification``
    # ends up on the cover + footer of every page; ``auditor`` /
    # ``engagement_id`` populate the signature block.
    client_logo_path: str | None = None
    client_color: str = ""  # e.g. "#0070d2"; empty = keep KRYON default
    classification: str = "CONFIDENTIAL"  # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
    auditor: str = "Kryon Autonomous Cybersecurity"
    engagement_id: str = ""
    reproducibility_hash: str = ""


class ReportSection(BaseModel):
    title: str
    content: str
    order: int


class ReportData(BaseModel):
    config: ReportConfig
    findings: list[Finding] = []
    sections: list[ReportSection] = []
    risk_score: float = 0.0
    executive_summary: str = ""
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
