"""NIS2 Directive compliance controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

NIS2_CONTROLS: list[ComplianceControl] = [
    # Article 21 — Cybersecurity Risk-Management Measures
    ComplianceControl(id="NIS2-21.1", title="Risk Analysis and Information System Security Policies", description="Policies on risk analysis and information system security shall be established", category="Risk Management", testing_procedures=["Policy documentation review", "Risk assessment review"], expected_evidence=["Risk analysis policy", "Risk register"]),
    ComplianceControl(id="NIS2-21.2a", title="Incident Handling", description="Procedures for incident handling including detection, analysis, containment, and response", category="Incident Handling", testing_procedures=["IR plan review", "Incident drill results"], expected_evidence=["Incident response plan", "Incident drill reports"]),
    ComplianceControl(id="NIS2-21.2b", title="Business Continuity and Crisis Management", description="Business continuity including backup management, disaster recovery, and crisis management", category="Business Continuity", testing_procedures=["BCP/DRP review", "DR test results"], expected_evidence=["Business continuity plan", "DR test reports"]),
    ComplianceControl(id="NIS2-21.2c", title="Supply Chain Security", description="Security in the supply chain including security aspects of relationships with direct suppliers", category="Supply Chain", testing_procedures=["Supply chain assessment"], expected_evidence=["Supplier security assessments", "Contractual clauses"]),
    ComplianceControl(id="NIS2-21.2d", title="Acquisition and Development Security", description="Security in network and information system acquisition, development, and maintenance including vulnerability handling and disclosure", category="Secure Development", testing_procedures=["SDLC review", "Vulnerability management review"], expected_evidence=["SDLC documentation", "Vulnerability reports"]),
    ComplianceControl(id="NIS2-21.2e", title="Vulnerability Handling and Disclosure", description="Policies and procedures for assessing the effectiveness of cybersecurity risk management measures", category="Vulnerability Management", testing_procedures=["Vulnerability management process review"], expected_evidence=["Vulnerability scan reports", "Remediation records"]),
    ComplianceControl(id="NIS2-21.2f", title="Cybersecurity Training and Awareness", description="Basic cyber hygiene practices and cybersecurity training", category="Awareness & Training", testing_procedures=["Training programme review"], expected_evidence=["Training records", "Awareness materials"]),
    ComplianceControl(id="NIS2-21.2g", title="Cryptography and Encryption", description="Policies and procedures regarding the use of cryptography and encryption", category="Encryption", testing_procedures=["Encryption controls review"], expected_evidence=["Cryptography policy", "Key management records"]),
    ComplianceControl(id="NIS2-21.2h", title="Human Resources Security", description="Human resources security, access control policies, and asset management", category="Access Control", testing_procedures=["HR security review", "Access control audit"], expected_evidence=["HR security policy", "Access control matrix"]),
    ComplianceControl(id="NIS2-21.2i", title="Multi-Factor Authentication", description="Use of multi-factor authentication or continuous authentication solutions, secured communications, and secured emergency communication systems", category="Authentication", testing_procedures=["MFA audit", "Communication security review"], expected_evidence=["MFA configuration", "Secure communication setup"]),

    # Article 23 — Reporting Obligations
    ComplianceControl(id="NIS2-23.1", title="Early Warning Notification", description="Submit early warning to CSIRT or competent authority within 24 hours of becoming aware of a significant incident", category="Incident Reporting", testing_procedures=["Reporting process review"], expected_evidence=["Notification templates", "Reporting timeline documentation"]),
    ComplianceControl(id="NIS2-23.2", title="Incident Notification", description="Submit incident notification within 72 hours with initial assessment including severity and impact", category="Incident Reporting", testing_procedures=["Notification procedure review"], expected_evidence=["Incident notification records", "Impact assessments"]),
    ComplianceControl(id="NIS2-23.3", title="Final Incident Report", description="Submit final report no later than one month after the incident notification including root cause analysis", category="Incident Reporting", testing_procedures=["Final report review"], expected_evidence=["Final incident reports", "Root cause analyses"]),

    # Article 20 — Governance
    ComplianceControl(id="NIS2-20.1", title="Management Body Accountability", description="Management bodies of essential and important entities shall approve cybersecurity risk management measures", category="Governance", testing_procedures=["Governance documentation review"], expected_evidence=["Board approvals", "Governance framework"]),
    ComplianceControl(id="NIS2-20.2", title="Management Body Training", description="Members of management bodies shall be required to follow cybersecurity training", category="Governance", testing_procedures=["Training records review"], expected_evidence=["Management training records", "Certification records"]),

    # Article 21 Additional — Network and System Security
    ComplianceControl(id="NIS2-21.3", title="Network Security", description="Appropriate measures to protect network and information systems including segmentation and access controls", category="Network Security", testing_procedures=["Network security assessment"], expected_evidence=["Network diagrams", "Firewall configurations"]),
    ComplianceControl(id="NIS2-21.4", title="Logging and Monitoring", description="Implement logging and monitoring to detect and analyze security events and anomalies", category="Monitoring", testing_procedures=["Log management review", "SIEM review"], expected_evidence=["Log configuration", "SIEM dashboard screenshots"]),
    ComplianceControl(id="NIS2-21.5", title="Physical and Environmental Security", description="Measures for physical and environmental security of network and information systems", category="Physical Security", testing_procedures=["Physical security audit"], expected_evidence=["Physical access logs", "Environmental controls"]),
]

# Keyword → NIS2 control ID mapping
_NIS2_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (["risk assessment", "risk analysis", "risk management", "risk register", "security policy"], ["NIS2-21.1"]),
    (["incident response", "incident handling", "containment", "triage", "forensic", "breach"], ["NIS2-21.2a"]),
    (["business continuity", "disaster recovery", "backup", "restore", "crisis management", "recovery"], ["NIS2-21.2b"]),
    (["supply chain", "supplier", "vendor", "third-party", "third party", "dependency"], ["NIS2-21.2c"]),
    (["sdlc", "secure development", "code review", "sast", "dast", "application security"], ["NIS2-21.2d"]),
    (["vulnerability", "cve-", "unpatched", "outdated", "vuln scan", "vulnerability scan", "patch"], ["NIS2-21.2e"]),
    (["encryption", "tls", "ssl", "cipher", "certificate", "plaintext", "unencrypted", "cryptography"], ["NIS2-21.2g"]),
    (["access control", "authorization", "privilege", "rbac", "permissions", "idor", "escalation"], ["NIS2-21.2h"]),
    (["mfa", "multi-factor", "two-factor", "2fa", "authentication", "credential", "password"], ["NIS2-21.2i"]),
    (["incident notification", "incident report", "early warning", "csirt"], ["NIS2-23.1", "NIS2-23.2", "NIS2-23.3"]),
    (["governance", "board", "management body", "accountability", "oversight"], ["NIS2-20.1", "NIS2-20.2"]),
    (["network security", "firewall", "segmentation", "open port", "port scan", "network isolation"], ["NIS2-21.3"]),
    (["logging", "monitoring", "siem", "ids", "ips", "anomaly", "detection", "audit log"], ["NIS2-21.4"]),
    (["malware", "ransomware", "trojan", "backdoor", "webshell", "virus"], ["NIS2-21.2a", "NIS2-21.4"]),
    (["sql injection", "xss", "injection", "rce", "ssrf", "command injection"], ["NIS2-21.2d", "NIS2-21.2e"]),
]


def map_finding_to_nis2_controls(finding: Finding) -> list[str]:
    """Map a finding to NIS2 Directive control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _NIS2_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
