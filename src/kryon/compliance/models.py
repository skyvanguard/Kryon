"""Compliance reporting models."""

from __future__ import annotations

from pydantic import BaseModel

from kryon.intelligence.models import Finding


class ComplianceControl(BaseModel):
    """A single compliance control/requirement.

    The trailing optional fields (``implementation_group`` ..
    ``verdict_mode``) were added for CIS Controls v8.1 and carry no meaning
    for frameworks that don't populate them — they stay at their defaults
    so every pre-existing control list keeps working unchanged.
    """

    id: str
    title: str
    description: str
    category: str
    testing_procedures: list[str] = []
    expected_evidence: list[str] = []
    # CIS Controls v8.1 metadata (optional; default-empty for other frameworks)
    implementation_group: int | None = None  # 1, 2 or 3 (lowest IG that includes it)
    security_function: str = ""  # Govern | Identify | Protect | Detect | Respond | Recover
    asset_type: str = ""  # Devices | Software | Data | Users | Network | Documentation
    safeguard: str = ""  # dotted safeguard id, e.g. "5.4" (== id for CIS)
    verdict_mode: str = "manual"  # "auto" (derived from a deterministic check) | "manual"


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
