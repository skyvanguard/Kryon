"""Pre-computed metrics for dashboard display."""

from __future__ import annotations

from kryon.evaluation.confidence import ConfidenceScorer
from kryon.evaluation.coverage import CoverageAnalyzer
from kryon.evaluation.risk_scorer import RiskScorer
from kryon.intelligence.models import Finding


class DashboardMetrics:
    """Aggregate metrics for dashboard consumption."""

    def __init__(self):
        self._scorer = RiskScorer()
        self._coverage = CoverageAnalyzer()
        self._confidence = ConfidenceScorer()

    def compute(self, findings: list[Finding], total_assets: int = 0) -> dict:
        """Compute all metrics for dashboard display."""
        risk = self._scorer.score_findings(findings)
        coverage = self._coverage.analyze(findings, total_assets)
        confidences = self._confidence.score_batch(findings)

        avg_confidence = sum(c.score for c in confidences) / len(confidences) if confidences else 0.0

        return {
            "risk_score": risk.total_score,
            "severity_distribution": risk.severity_distribution,
            "top_risks": risk.top_risks,
            "total_findings": len(findings),
            "coverage": {
                "assets_scanned": coverage.assets_scanned,
                "total_assets": coverage.total_assets,
                "coverage_percent": coverage.coverage_percent,
                "mitre_tactics": coverage.mitre_tactics_covered,
                "mitre_techniques": coverage.mitre_techniques_tested,
            },
            "avg_confidence": round(avg_confidence, 3),
        }
