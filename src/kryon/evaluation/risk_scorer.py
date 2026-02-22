"""Aggregate risk scoring from findings."""

from __future__ import annotations

from kryon.intelligence.models import Finding, Severity
from kryon.evaluation.models import RiskScore

_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}


class RiskScorer:
    """Calculate aggregate risk scores."""

    def score_findings(self, findings: list[Finding]) -> RiskScore:
        """Weighted CVSS-based risk score (0-100)."""
        if not findings:
            return RiskScore(total_score=0.0, severity_distribution={})

        # Base score from severity weights
        total_weight = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        max_ref = 10 * _SEVERITY_WEIGHTS[Severity.CRITICAL]  # 100 = 10 criticals
        score = min(total_weight / max_ref * 100, 100.0)

        # Boost for high-risk indicators
        for f in findings:
            if f.cve:
                if f.cve.epss_score and f.cve.epss_score > 0.5:
                    score = min(score + 2.0, 100.0)
                if f.cve.cisa_kev:
                    score = min(score + 3.0, 100.0)
                if f.cve.exploit_available:
                    score = min(score + 1.5, 100.0)

        # Severity distribution
        dist: dict[str, int] = {}
        for f in findings:
            dist[f.severity.value] = dist.get(f.severity.value, 0) + 1

        # Top risks
        top = sorted(
            [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)],
            key=lambda x: _SEVERITY_WEIGHTS.get(x.severity, 0),
            reverse=True,
        )
        top_risks = [f.title for f in top[:5]]

        return RiskScore(
            total_score=round(score, 1),
            severity_distribution=dist,
            top_risks=top_risks,
        )
