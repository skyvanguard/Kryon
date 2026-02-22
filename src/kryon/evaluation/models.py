"""Evaluation data models."""

from __future__ import annotations

from pydantic import BaseModel

from kryon.intelligence.models import Finding


class CoverageMetrics(BaseModel):
    total_assets: int = 0
    assets_scanned: int = 0
    coverage_percent: float = 0.0
    ports_scanned: int = 0
    web_endpoints_tested: int = 0
    mitre_tactics_covered: int = 0
    mitre_techniques_tested: int = 0


class ConfidenceScore(BaseModel):
    finding_id: str
    score: float  # 0.0-1.0
    factors: dict[str, float] = {}


class RiskScore(BaseModel):
    total_score: float  # 0-100
    severity_distribution: dict[str, int] = {}
    top_risks: list[str] = []
    trend: str = "stable"  # improving, stable, worsening


class ScanComparison(BaseModel):
    scan_before_id: str = ""
    scan_after_id: str = ""
    new_findings: list[Finding] = []
    remediated_findings: list[Finding] = []
    persistent_findings: list[Finding] = []
    risk_delta: float = 0.0
    summary: str = ""
