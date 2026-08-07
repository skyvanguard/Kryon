"""Attack surface coverage calculation."""

from __future__ import annotations

from kryon.evaluation.models import CoverageMetrics
from kryon.intelligence.models import Finding


class CoverageAnalyzer:
    """Calculate attack surface coverage from findings."""

    def analyze(self, findings: list[Finding], total_assets: int = 0) -> CoverageMetrics:
        """Calculate coverage metrics from findings."""
        assets_seen = {f.affected_asset for f in findings}
        # MITRE coverage
        tactics_seen: set[str] = set()
        techniques_seen: set[str] = set()
        for f in findings:
            for m in f.mitre:
                tactics_seen.add(m.tactic_id)
                techniques_seen.add(m.technique_id)

        total = total_assets if total_assets > 0 else len(assets_seen)
        coverage = (len(assets_seen) / total * 100) if total > 0 else 0.0

        return CoverageMetrics(
            total_assets=total,
            assets_scanned=len(assets_seen),
            coverage_percent=round(coverage, 1),
            mitre_tactics_covered=len(tactics_seen),
            mitre_techniques_tested=len(techniques_seen),
        )
