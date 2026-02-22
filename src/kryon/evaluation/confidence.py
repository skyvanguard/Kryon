"""Finding confidence scoring."""

from __future__ import annotations

from kryon.intelligence.models import Finding
from kryon.evaluation.models import ConfidenceScore


class ConfidenceScorer:
    """Score confidence of individual findings."""

    def score(self, finding: Finding) -> ConfidenceScore:
        """Calculate confidence score based on multiple factors."""
        factors: dict[str, float] = {}

        # Evidence quality (0.0-0.3)
        if finding.evidence:
            evidence_len = len(finding.evidence)
            factors["evidence_quality"] = min(evidence_len / 500, 0.3)
        else:
            factors["evidence_quality"] = 0.0

        # Tool reliability (0.0-0.25)
        high_confidence_tools = {"sqlmap", "nmap", "nuclei", "burpsuite", "metasploit", "testssl"}
        if finding.tool_source.lower() in high_confidence_tools:
            factors["tool_reliability"] = 0.25
        elif finding.tool_source:
            factors["tool_reliability"] = 0.15
        else:
            factors["tool_reliability"] = 0.05

        # CVE reference (0.0-0.25)
        if finding.cve:
            factors["cve_reference"] = 0.2
            if finding.cve.cvss_score:
                factors["cve_reference"] = 0.25
        else:
            factors["cve_reference"] = 0.0

        # MITRE mapping (0.0-0.2)
        if finding.mitre:
            avg_conf = sum(m.confidence for m in finding.mitre) / len(finding.mitre)
            factors["mitre_mapping"] = avg_conf * 0.2
        else:
            factors["mitre_mapping"] = 0.0

        total = sum(factors.values())
        return ConfidenceScore(
            finding_id=finding.id,
            score=round(min(total, 1.0), 3),
            factors=factors,
        )

    def score_batch(self, findings: list[Finding]) -> list[ConfidenceScore]:
        """Score confidence for a batch of findings."""
        return [self.score(f) for f in findings]
