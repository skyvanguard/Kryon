"""Zero Trust Architecture assessment controls and finding mapping."""

from __future__ import annotations

from pydantic import BaseModel, Field

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

ZERO_TRUST_CONTROLS: list[ComplianceControl] = [
    # Identity Pillar
    ComplianceControl(
        id="ZT-ID-01",
        title="Strong Authentication",
        description="All users authenticate with phishing-resistant MFA before accessing any resource",
        category="Identity",
        testing_procedures=["MFA configuration audit", "Phishing-resistant method check"],
        expected_evidence=["MFA enrollment records", "FIDO2/WebAuthn configuration"],
    ),
    ComplianceControl(
        id="ZT-ID-02",
        title="Identity Governance",
        description="Continuous identity validation and lifecycle management with automated provisioning and deprovisioning",
        category="Identity",
        testing_procedures=["Identity lifecycle review"],
        expected_evidence=["IAM policy", "Provisioning/deprovisioning logs"],
    ),
    ComplianceControl(
        id="ZT-ID-03",
        title="Conditional Access Policies",
        description="Access decisions incorporate real-time risk signals including user behavior, location, and device state",
        category="Identity",
        testing_procedures=["Conditional access policy review"],
        expected_evidence=["Policy configurations", "Risk signal integrations"],
    ),
    ComplianceControl(
        id="ZT-ID-04",
        title="Least Privilege Access",
        description="Users and service accounts are granted minimum necessary permissions with just-in-time and just-enough-access",
        category="Identity",
        testing_procedures=["Privilege review", "JIT access audit"],
        expected_evidence=["Role assignments", "Privilege escalation logs"],
    ),
    # Device Pillar
    ComplianceControl(
        id="ZT-DEV-01",
        title="Device Inventory and Compliance",
        description="All devices are inventoried and must meet compliance requirements before accessing resources",
        category="Device",
        testing_procedures=["Device inventory review", "Compliance check"],
        expected_evidence=["MDM enrollment", "Compliance status reports"],
    ),
    ComplianceControl(
        id="ZT-DEV-02",
        title="Endpoint Detection and Response",
        description="All endpoints run EDR with continuous monitoring and automated threat response capabilities",
        category="Device",
        testing_procedures=["EDR deployment review"],
        expected_evidence=["EDR agent status", "Detection rule coverage"],
    ),
    ComplianceControl(
        id="ZT-DEV-03",
        title="Device Health Attestation",
        description="Device health is continuously assessed and incorporated into access decisions",
        category="Device",
        testing_procedures=["Health attestation policy review"],
        expected_evidence=["Health check configurations", "Device compliance logs"],
    ),
    ComplianceControl(
        id="ZT-DEV-04",
        title="Patch and Vulnerability Management",
        description="Devices are patched and vulnerability-free as a condition for resource access",
        category="Device",
        testing_procedures=["Patch compliance audit"],
        expected_evidence=["Patch status reports", "Vulnerability scan results"],
    ),
    # Network Pillar
    ComplianceControl(
        id="ZT-NET-01",
        title="Micro-Segmentation",
        description="Network is micro-segmented with granular access controls between all zones and workloads",
        category="Network",
        testing_procedures=["Segmentation testing", "Lateral movement testing"],
        expected_evidence=["Segmentation rules", "Network flow logs"],
    ),
    ComplianceControl(
        id="ZT-NET-02",
        title="Encrypted Communications",
        description="All network traffic is encrypted regardless of network location (internal or external)",
        category="Network",
        testing_procedures=["Traffic encryption audit"],
        expected_evidence=["TLS configuration", "mTLS certificates"],
    ),
    ComplianceControl(
        id="ZT-NET-03",
        title="Network Visibility and Analytics",
        description="Full network traffic visibility with real-time analytics and anomaly detection",
        category="Network",
        testing_procedures=["Network monitoring review"],
        expected_evidence=["NDR configuration", "Traffic analysis dashboards"],
    ),
    ComplianceControl(
        id="ZT-NET-04",
        title="Software-Defined Perimeter",
        description="Network perimeter is software-defined with per-session access instead of broad VPN tunnels",
        category="Network",
        testing_procedures=["SDP/ZTNA configuration review"],
        expected_evidence=["ZTNA policy", "Per-session access logs"],
    ),
    # Application Pillar
    ComplianceControl(
        id="ZT-APP-01",
        title="Application Access Control",
        description="All application access is brokered through an identity-aware proxy with per-request authorization",
        category="Application",
        testing_procedures=["Application proxy review"],
        expected_evidence=["Proxy configuration", "Application access logs"],
    ),
    ComplianceControl(
        id="ZT-APP-02",
        title="Application Security Testing",
        description="All applications undergo continuous security testing including SAST, DAST, and runtime protection",
        category="Application",
        testing_procedures=["AppSec programme review"],
        expected_evidence=["SAST/DAST reports", "RASP configuration"],
    ),
    ComplianceControl(
        id="ZT-APP-03",
        title="API Security",
        description="All APIs enforce authentication, authorization, rate limiting, and input validation",
        category="Application",
        testing_procedures=["API security assessment"],
        expected_evidence=["API gateway configuration", "API security test results"],
    ),
    # Data Pillar
    ComplianceControl(
        id="ZT-DATA-01",
        title="Data Classification and Labeling",
        description="All data is classified, labeled, and protected according to its sensitivity level",
        category="Data",
        testing_procedures=["Data classification review"],
        expected_evidence=["Classification policy", "Data inventory with labels"],
    ),
    ComplianceControl(
        id="ZT-DATA-02",
        title="Data Encryption",
        description="Data is encrypted at rest and in transit with organization-managed keys",
        category="Data",
        testing_procedures=["Encryption-at-rest and in-transit audit"],
        expected_evidence=["Encryption configurations", "Key management records"],
    ),
    ComplianceControl(
        id="ZT-DATA-03",
        title="Data Loss Prevention",
        description="DLP controls prevent unauthorized data exfiltration across all channels",
        category="Data",
        testing_procedures=["DLP configuration review"],
        expected_evidence=["DLP policy", "Incident reports"],
    ),
    ComplianceControl(
        id="ZT-DATA-04",
        title="Data Access Governance",
        description="Data access is governed by fine-grained policies based on user identity, device state, and context",
        category="Data",
        testing_procedures=["Data access policy review"],
        expected_evidence=["ABAC/PBAC policies", "Data access logs"],
    ),
    # Analytics & Automation Pillar
    ComplianceControl(
        id="ZT-AA-01",
        title="Security Information and Event Management",
        description="Centralized SIEM with correlation across all zero trust pillars for holistic threat detection",
        category="Analytics & Automation",
        testing_procedures=["SIEM coverage review"],
        expected_evidence=["SIEM configuration", "Log source inventory"],
    ),
    ComplianceControl(
        id="ZT-AA-02",
        title="Security Orchestration and Automated Response",
        description="Automated response playbooks for common threat scenarios reducing mean time to respond",
        category="Analytics & Automation",
        testing_procedures=["SOAR playbook review"],
        expected_evidence=["Playbook library", "Automation execution logs"],
    ),
    ComplianceControl(
        id="ZT-AA-03",
        title="User and Entity Behavior Analytics",
        description="UEBA baselines normal behavior and detects anomalies indicative of compromise or insider threat",
        category="Analytics & Automation",
        testing_procedures=["UEBA configuration review"],
        expected_evidence=["Behavior baselines", "Anomaly detection rules"],
    ),
    ComplianceControl(
        id="ZT-AA-04",
        title="Continuous Monitoring and Validation",
        description="All trust decisions are continuously validated and never implicitly trusted based on network location",
        category="Analytics & Automation",
        testing_procedures=["Continuous monitoring review"],
        expected_evidence=["Monitoring dashboards", "Re-authentication triggers"],
    ),
]

# Keyword → Zero Trust control ID mapping
_ZT_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (["mfa", "multi-factor", "two-factor", "2fa", "fido", "webauthn", "phishing-resistant"], ["ZT-ID-01"]),
    (["identity", "iam", "provisioning", "deprovisioning", "user lifecycle", "credential"], ["ZT-ID-02"]),
    (["conditional access", "risk signal", "adaptive auth", "context-aware"], ["ZT-ID-03"]),
    (
        ["least privilege", "privilege escalation", "privesc", "excessive permissions", "rbac", "jit access"],
        ["ZT-ID-04"],
    ),
    (
        ["endpoint", "device compliance", "mdm", "device inventory", "edr", "antivirus", "malware"],
        ["ZT-DEV-01", "ZT-DEV-02"],
    ),
    (["unpatched", "outdated", "patch", "vulnerability", "cve-", "end of life", "eol"], ["ZT-DEV-04"]),
    (["segmentation", "lateral movement", "micro-segmentation", "network isolation", "vlan"], ["ZT-NET-01"]),
    (
        ["encryption", "tls", "ssl", "plaintext", "unencrypted", "certificate", "mtls", "cipher"],
        ["ZT-NET-02", "ZT-DATA-02"],
    ),
    (["network monitoring", "ndr", "traffic analysis", "ids", "ips", "anomaly"], ["ZT-NET-03"]),
    (["vpn", "ztna", "sdp", "remote access", "zero trust network"], ["ZT-NET-04"]),
    (
        ["sql injection", "xss", "injection", "rce", "ssrf", "csrf", "sast", "dast", "application security"],
        ["ZT-APP-02"],
    ),
    (["api", "api key", "rate limit", "api gateway", "rest", "graphql"], ["ZT-APP-03"]),
    (["data classification", "sensitive data", "data exposure", "pii", "data labeling"], ["ZT-DATA-01"]),
    (["data leak", "data loss", "exfiltration", "dlp", "data breach"], ["ZT-DATA-03"]),
    (["siem", "log correlation", "centralized logging", "security event", "audit log"], ["ZT-AA-01"]),
    (["soar", "automated response", "playbook", "orchestration", "incident response"], ["ZT-AA-02"]),
    (["behavior analytics", "ueba", "insider threat", "anomalous behavior", "user behavior"], ["ZT-AA-03"]),
    (["monitoring", "continuous validation", "continuous monitoring", "detection", "alert"], ["ZT-AA-04"]),
]

# Pillar definitions for Zero Trust maturity assessment
_ZT_PILLARS: dict[str, list[str]] = {
    "Identity": ["ZT-ID-01", "ZT-ID-02", "ZT-ID-03", "ZT-ID-04"],
    "Device": ["ZT-DEV-01", "ZT-DEV-02", "ZT-DEV-03", "ZT-DEV-04"],
    "Network": ["ZT-NET-01", "ZT-NET-02", "ZT-NET-03", "ZT-NET-04"],
    "Application": ["ZT-APP-01", "ZT-APP-02", "ZT-APP-03"],
    "Data": ["ZT-DATA-01", "ZT-DATA-02", "ZT-DATA-03", "ZT-DATA-04"],
    "Analytics & Automation": ["ZT-AA-01", "ZT-AA-02", "ZT-AA-03", "ZT-AA-04"],
}


class ZeroTrustAssessment(BaseModel):
    """Assessment result for a single Zero Trust pillar."""

    pillar: str
    maturity_level: str = Field(
        default="Traditional",
        description="Maturity level: Traditional, Initial, Advanced, or Optimal",
    )
    controls_assessed: int = 0
    controls_met: int = 0
    gaps: list[str] = Field(default_factory=list)

    @property
    def score_percentage(self) -> float:
        if self.controls_assessed == 0:
            return 0.0
        return round((self.controls_met / self.controls_assessed) * 100, 1)


def _determine_maturity(controls_met: int, controls_total: int) -> str:
    """Determine Zero Trust maturity level based on control coverage."""
    if controls_total == 0:
        return "Traditional"
    ratio = controls_met / controls_total
    if ratio >= 0.9:
        return "Optimal"
    if ratio >= 0.65:
        return "Advanced"
    if ratio >= 0.3:
        return "Initial"
    return "Traditional"


def map_finding_to_zero_trust_controls(finding: Finding) -> list[str]:
    """Map a finding to Zero Trust control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _ZT_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)


def assess_zero_trust(findings: list[Finding]) -> list[ZeroTrustAssessment]:
    """Assess Zero Trust maturity across all pillars based on findings.

    Findings indicate gaps — controls that have findings mapped to them
    are considered NOT met (they represent vulnerabilities or issues).
    Controls with no mapped findings are considered met.
    """
    # Collect all control IDs that have findings mapped to them (gaps)
    failing_controls: set[str] = set()
    for finding in findings:
        mapped = map_finding_to_zero_trust_controls(finding)
        failing_controls.update(mapped)

    assessments: list[ZeroTrustAssessment] = []
    for pillar, control_ids in _ZT_PILLARS.items():
        total = len(control_ids)
        gaps = [cid for cid in control_ids if cid in failing_controls]
        met = total - len(gaps)
        maturity = _determine_maturity(met, total)
        assessments.append(
            ZeroTrustAssessment(
                pillar=pillar,
                maturity_level=maturity,
                controls_assessed=total,
                controls_met=met,
                gaps=gaps,
            )
        )

    return assessments
