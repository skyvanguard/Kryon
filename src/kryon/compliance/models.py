"""Compliance reporting models."""

from __future__ import annotations

from pydantic import BaseModel

from kryon.intelligence.models import Finding


class ComplianceControl(BaseModel):
    """A single compliance control/requirement."""

    id: str
    title: str
    description: str
    category: str
    testing_procedures: list[str] = []
    expected_evidence: list[str] = []


class ControlEvidence(BaseModel):
    """Evidence for a specific control assessment."""

    control_id: str
    status: str = "pass"  # 'pass' | 'fail' | 'partial' | 'not_applicable'
    findings: list[Finding] = []
    recommendation: str = ""


class ComplianceReport(BaseModel):
    """Complete compliance assessment report."""

    framework: str
    controls_assessed: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    evidence: list[ControlEvidence] = []

    @property
    def compliance_percentage(self) -> float:
        if self.controls_assessed == 0:
            return 100.0
        return round((self.controls_passed / self.controls_assessed) * 100, 1)
