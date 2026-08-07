"""Pydantic models shared across all KRYON pillars."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(str, Enum):
    UNVALIDATED = "unvalidated"
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    FALSE_POSITIVE = "false_positive"


class MITREMapping(BaseModel):
    """Mapping of a finding to a MITRE ATT&CK technique."""

    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    subtechnique: str | None = None
    subtechnique_id: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class CVEDetail(BaseModel):
    """Enriched CVE information."""

    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cpe_affected: list[str] = []
    exploit_available: bool = False
    exploit_refs: list[str] = []
    cisa_kev: bool = False
    references: list[str] = []


class IoC(BaseModel):
    """Indicator of Compromise extracted from scan results."""

    type: str  # ip, domain, hash, url, email
    value: str
    source: str = ""
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    tags: list[str] = []


class Finding(BaseModel):
    """Core finding model used across all pillars."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str
    description: str
    severity: Severity
    cvss_score: float | None = None
    cve: CVEDetail | None = None
    mitre: list[MITREMapping] = []
    iocs: list[IoC] = []
    affected_asset: str
    evidence: str = ""
    tool_source: str = ""
    remediation: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    exploit_proof: str = ""
    validated_at: str | None = None
    validation_method: str = ""
    # F210 anti-FP band, unified from the engage pipeline's Finding (previously
    # dropped when findings crossed into this model). A confidence CEILING that
    # only lowers: confirmed (proven) > heuristic > inferred. Drives the
    # validated-exploitable program metric.
    verification_level: str = "confirmed"
    needs_verification: bool = False

    @property
    def is_validated_exploitable(self) -> bool:
        """True when the finding was proven (not heuristic/inferred and not
        flagged for manual review). This is the 'validated exploitable' signal
        the funnel/metrics count on."""
        return self.verification_level == "confirmed" and not self.needs_verification
