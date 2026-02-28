"""Business risk scoring — contextual risk with asset criticality and exposure."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

# Criticality multipliers
CRITICALITY_MULTIPLIERS = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5,
}

# Exposure multipliers
EXPOSURE_MULTIPLIERS = {
    "public": 1.8,
    "dmz": 1.3,
    "internal": 1.0,
    "isolated": 0.6,
}

# Base severity scores
SEVERITY_SCORES = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.0,
}

# Business impact categories
IMPACT_CATEGORIES = ["data_breach", "service_disruption", "regulatory", "reputational"]


class BusinessRiskScorer:
    """Calculate contextual risk scores incorporating asset criticality and exposure."""

    def calculate_contextual_risk(
        self,
        finding: dict,
        asset_criticality: str = "medium",
        exposure_level: str = "internal",
    ) -> float:
        """Calculate risk score: base * criticality * exposure * exploitability."""
        severity = self._extract_severity(finding)
        base = SEVERITY_SCORES.get(severity, 4.0)
        crit = CRITICALITY_MULTIPLIERS.get(asset_criticality.lower(), 1.0)
        expo = EXPOSURE_MULTIPLIERS.get(exposure_level.lower(), 1.0)

        # Exploitability factor from CVSS or default
        exploitability = self._get_exploitability(finding)

        score = base * crit * expo * exploitability
        return min(round(score, 1), 100.0)

    def categorize_business_impact(self, findings: list[dict]) -> dict:
        """Categorize findings by business impact type."""
        impact: dict[str, int] = {cat: 0 for cat in IMPACT_CATEGORIES}

        for f in findings:
            severity = self._extract_severity(f)
            desc = self._extract_field(f, "description", "").lower()
            title = self._extract_field(f, "title", "").lower()
            text = f"{desc} {title}"

            if any(kw in text for kw in ["data", "exfiltrat", "dump", "leak", "credential", "password"]):
                impact["data_breach"] += SEVERITY_SCORES.get(severity, 1)
            if any(kw in text for kw in ["dos", "denial", "crash", "availability", "outage"]):
                impact["service_disruption"] += SEVERITY_SCORES.get(severity, 1)
            if any(kw in text for kw in ["pci", "hipaa", "gdpr", "compliance", "audit"]):
                impact["regulatory"] += SEVERITY_SCORES.get(severity, 1)
            if any(kw in text for kw in ["deface", "public", "customer", "brand"]):
                impact["reputational"] += SEVERITY_SCORES.get(severity, 1)

            # Default: highest severity findings always count as data breach risk
            if severity in ("critical", "high") and not any(impact[cat] for cat in IMPACT_CATEGORIES):
                impact["data_breach"] += SEVERITY_SCORES.get(severity, 1)

        return {k: round(v, 1) for k, v in impact.items()}

    def get_risk_overview(self, store, client_id: str = "") -> dict:
        """Get aggregated risk dashboard data."""
        if client_id:
            findings_raw = store.get_client_findings(client_id, status="open")
        else:
            findings_raw = store.list_all_findings(status="open", limit=500)

        findings = []
        for f in findings_raw:
            fj = f.finding_json if hasattr(f, "finding_json") else f.get("finding_json", "{}")
            try:
                parsed = json.loads(fj) if isinstance(fj, str) else fj
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            findings.append(parsed)

        if not findings:
            return {"total_score": 0.0, "impact_breakdown": {cat: 0 for cat in IMPACT_CATEGORIES}, "finding_count": 0}

        # Calculate average contextual risk
        scores = [self.calculate_contextual_risk(f) for f in findings]
        total_score = min(round(sum(scores) / len(scores) * 10, 1), 100.0)

        impact = self.categorize_business_impact(findings)

        return {
            "total_score": total_score,
            "impact_breakdown": impact,
            "finding_count": len(findings),
            "severity_distribution": self._severity_dist(findings),
        }

    def _extract_severity(self, finding: dict) -> str:
        return str(finding.get("severity", "medium")).lower()

    def _extract_field(self, finding: dict, field: str, default: str = "") -> str:
        return str(finding.get(field, default))

    def _get_exploitability(self, finding: dict) -> float:
        cvss = finding.get("cvss_score")
        if cvss and isinstance(cvss, (int, float)):
            return min(cvss / 10.0, 1.0)
        return 0.7  # default

    def _severity_dist(self, findings: list[dict]) -> dict[str, int]:
        dist: dict[str, int] = {}
        for f in findings:
            sev = self._extract_severity(f)
            dist[sev] = dist.get(sev, 0) + 1
        return dist
