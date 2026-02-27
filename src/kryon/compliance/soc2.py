"""SOC 2 Type II Trust Services Criteria controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

SOC2_TSC_CONTROLS: list[ComplianceControl] = [
    # Security (Common Criteria)
    ComplianceControl(id="CC6.1", title="Logical and Physical Access Controls", description="Logical access security software, infrastructure, and architectures have been implemented", category="Security", testing_procedures=["Access control review"], expected_evidence=["Access policy", "Config"]),
    ComplianceControl(id="CC6.2", title="User Registration and Authorization", description="New users are registered and authorized", category="Security", testing_procedures=["User provisioning review"], expected_evidence=["Provisioning process"]),
    ComplianceControl(id="CC6.3", title="Role-Based Access", description="Role-based access controls are used to support segregation of duties", category="Security", testing_procedures=["RBAC review"], expected_evidence=["Role matrix"]),
    ComplianceControl(id="CC6.6", title="System Boundaries Security", description="System boundaries are secured against unauthorized access", category="Security", testing_procedures=["Perimeter testing"], expected_evidence=["Firewall config"]),
    ComplianceControl(id="CC6.7", title="Transmission Security", description="Data transmitted between boundaries is protected", category="Security", testing_procedures=["Encryption testing"], expected_evidence=["TLS config"]),
    ComplianceControl(id="CC6.8", title="Malicious Software Prevention", description="Controls to prevent or detect malicious software", category="Security", testing_procedures=["AV verification"], expected_evidence=["AV reports"]),
    ComplianceControl(id="CC7.1", title="Monitoring Activities", description="Monitoring of infrastructure and software for anomalies", category="Security", testing_procedures=["Log review"], expected_evidence=["Monitoring config"]),
    ComplianceControl(id="CC7.2", title="Anomaly Detection", description="Anomalies are investigated and remediated", category="Security", testing_procedures=["Incident review"], expected_evidence=["Incident logs"]),
    ComplianceControl(id="CC7.3", title="Vulnerability Management", description="Vulnerabilities are identified, assessed, and remediated", category="Security", testing_procedures=["Vuln scanning"], expected_evidence=["Scan reports"]),
    ComplianceControl(id="CC7.4", title="Incident Response", description="Security incidents are identified and responded to", category="Security", testing_procedures=["IR plan review"], expected_evidence=["IR plan"]),
    ComplianceControl(id="CC8.1", title="Change Management", description="Changes are authorized, tested, and approved", category="Security", testing_procedures=["Change review"], expected_evidence=["Change logs"]),
    # Availability
    ComplianceControl(id="A1.1", title="Capacity Management", description="Current processing capacity and usage are maintained", category="Availability", testing_procedures=["Capacity review"], expected_evidence=["Capacity reports"]),
    ComplianceControl(id="A1.2", title="Recovery Planning", description="Recovery operations are planned and tested", category="Availability", testing_procedures=["DR test review"], expected_evidence=["DR test results"]),
    # Processing Integrity
    ComplianceControl(id="PI1.1", title="Processing Accuracy", description="System processing is complete, valid, accurate, and timely", category="Processing Integrity", testing_procedures=["Data integrity review"], expected_evidence=["Validation logs"]),
    # Confidentiality
    ComplianceControl(id="C1.1", title="Confidential Information Classification", description="Confidential information is identified and classified", category="Confidentiality", testing_procedures=["Classification review"], expected_evidence=["Classification policy"]),
    ComplianceControl(id="C1.2", title="Confidential Information Disposal", description="Confidential information is destroyed when no longer needed", category="Confidentiality", testing_procedures=["Disposal review"], expected_evidence=["Disposal records"]),
    # Privacy
    ComplianceControl(id="P1.1", title="Privacy Notice", description="Privacy notice is provided to data subjects", category="Privacy", testing_procedures=["Notice review"], expected_evidence=["Privacy policy"]),
    ComplianceControl(id="P6.1", title="Data Quality", description="Personal information is accurate and complete", category="Privacy", testing_procedures=["Data quality review"], expected_evidence=["Data audit"]),
]

_SOC2_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (["access control", "authorization", "idor", "privilege escalation", "privesc"], ["CC6.1", "CC6.3"]),
    (["default password", "default credential", "user provisioning"], ["CC6.2"]),
    (["open port", "firewall", "network segmentation", "service exposure"], ["CC6.6"]),
    (["weak ssl", "weak tls", "unencrypted", "plaintext", "certificate"], ["CC6.7"]),
    (["malware", "trojan", "ransomware"], ["CC6.8"]),
    (["logging", "monitoring", "audit trail", "audit log"], ["CC7.1"]),
    (["anomaly", "intrusion", "suspicious activity"], ["CC7.2"]),
    (["vulnerability", "cve-", "unpatched", "outdated", "end of life"], ["CC7.3"]),
    (["incident", "breach", "compromise"], ["CC7.4"]),
    (["sql injection", "xss", "injection", "ssrf", "csrf", "rce", "command injection"], ["CC7.3", "CC6.1"]),
    (["brute force", "weak password", "password policy", "credential stuffing"], ["CC6.1", "CC6.2"]),
    (["data exposure", "sensitive data", "information disclosure", "data leak"], ["C1.1"]),
    (["backup", "recovery", "disaster"], ["A1.2"]),
    (["mfa", "multi-factor", "two-factor"], ["CC6.1"]),
]


def map_finding_to_soc2_controls(finding: Finding) -> list[str]:
    """Map a finding to SOC 2 control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _SOC2_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
