"""Before/after scan comparison."""

from __future__ import annotations

from kryon.evaluation.models import ScanComparison
from kryon.evaluation.risk_scorer import RiskScorer
from kryon.intelligence.models import Finding


class ScanComparator:
    """Delta analysis between two scan results."""

    def __init__(self):
        self._scorer = RiskScorer()

    def compare(
        self,
        before: list[Finding],
        after: list[Finding],
        before_id: str = "",
        after_id: str = "",
    ) -> ScanComparison:
        """Compare two sets of findings to identify changes."""
        before_keys = {self._key(f): f for f in before}
        after_keys = {self._key(f): f for f in after}

        new_findings = [f for k, f in after_keys.items() if k not in before_keys]
        remediated = [f for k, f in before_keys.items() if k not in after_keys]
        persistent = [f for k, f in after_keys.items() if k in before_keys]

        score_before = self._scorer.score_findings(before).total_score
        score_after = self._scorer.score_findings(after).total_score
        risk_delta = round(score_after - score_before, 1)

        trend = "improving" if risk_delta < 0 else "stable" if risk_delta == 0 else "worsening"

        summary_parts = []
        if new_findings:
            summary_parts.append(f"{len(new_findings)} new findings")
        if remediated:
            summary_parts.append(f"{len(remediated)} remediated")
        if persistent:
            summary_parts.append(f"{len(persistent)} persistent")
        summary_parts.append(f"risk delta: {risk_delta:+.1f} ({trend})")

        return ScanComparison(
            scan_before_id=before_id,
            scan_after_id=after_id,
            new_findings=new_findings,
            remediated_findings=remediated,
            persistent_findings=persistent,
            risk_delta=risk_delta,
            summary=", ".join(summary_parts),
        )

    def _key(self, f: Finding) -> str:
        """Dedup key for a finding."""
        return f"{f.title}|{f.affected_asset}"
