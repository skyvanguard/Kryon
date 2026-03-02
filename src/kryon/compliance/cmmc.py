"""CMMC 2.0 Level 2 compliance controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

CMMC_CONTROLS: list[ComplianceControl] = [
    # Access Control (AC)
    ComplianceControl(
        id="CMMC-AC.L2-3.1.1",
        title="Authorized Access Control",
        description="Limit information system access to authorized users, processes, or devices",
        category="Access Control",
        testing_procedures=["Access control policy review", "Account audit"],
        expected_evidence=["Access control policy", "User access list"],
    ),
    ComplianceControl(
        id="CMMC-AC.L2-3.1.2",
        title="Transaction & Function Control",
        description="Limit information system access to the types of transactions and functions that authorized users are permitted to execute",
        category="Access Control",
        testing_procedures=["Function-level access review"],
        expected_evidence=["Role-based access matrix", "Authorization configs"],
    ),
    ComplianceControl(
        id="CMMC-AC.L2-3.1.5",
        title="Least Privilege",
        description="Employ the principle of least privilege, including for specific security functions and privileged accounts",
        category="Access Control",
        testing_procedures=["Privilege review"],
        expected_evidence=["Least privilege policy", "Privileged account inventory"],
    ),
    ComplianceControl(
        id="CMMC-AC.L2-3.1.7",
        title="Privileged Functions",
        description="Prevent non-privileged users from executing privileged functions and audit the execution of such functions",
        category="Access Control",
        testing_procedures=["Privilege escalation testing"],
        expected_evidence=["Sudo/UAC configuration", "Audit logs"],
    ),
    ComplianceControl(
        id="CMMC-AC.L2-3.1.12",
        title="Remote Access Control",
        description="Monitor and control remote access sessions",
        category="Access Control",
        testing_procedures=["Remote access review"],
        expected_evidence=["VPN configuration", "Remote access logs"],
    ),
    # Awareness & Training (AT)
    ComplianceControl(
        id="CMMC-AT.L2-3.2.1",
        title="Role-Based Risk Awareness",
        description="Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities",
        category="Awareness & Training",
        testing_procedures=["Training records review"],
        expected_evidence=["Training completion records", "Awareness materials"],
    ),
    # Audit & Accountability (AU)
    ComplianceControl(
        id="CMMC-AU.L2-3.3.1",
        title="System Auditing",
        description="Create, protect, and retain information system audit records to enable monitoring, analysis, investigation, and reporting",
        category="Audit & Accountability",
        testing_procedures=["Audit log review"],
        expected_evidence=["Audit log samples", "Retention configuration"],
    ),
    ComplianceControl(
        id="CMMC-AU.L2-3.3.2",
        title="User Accountability",
        description="Ensure that the actions of individual information system users can be uniquely traced to those users",
        category="Audit & Accountability",
        testing_procedures=["User attribution testing"],
        expected_evidence=["Log correlation results", "User identification records"],
    ),
    # Configuration Management (CM)
    ComplianceControl(
        id="CMMC-CM.L2-3.4.1",
        title="System Baselining",
        description="Establish and maintain baseline configurations and inventories of organizational systems throughout their system development life cycles",
        category="Configuration Management",
        testing_procedures=["Baseline configuration review"],
        expected_evidence=["Configuration baselines", "CMDB records"],
    ),
    ComplianceControl(
        id="CMMC-CM.L2-3.4.2",
        title="Security Configuration Enforcement",
        description="Establish and enforce security configuration settings for information technology products employed in organizational systems",
        category="Configuration Management",
        testing_procedures=["Configuration compliance scan"],
        expected_evidence=["Hardening scan results", "STIG compliance reports"],
    ),
    ComplianceControl(
        id="CMMC-CM.L2-3.4.6",
        title="Least Functionality",
        description="Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities",
        category="Configuration Management",
        testing_procedures=["Service/port review"],
        expected_evidence=["Running services list", "Disabled services log"],
    ),
    # Identification & Authentication (IA)
    ComplianceControl(
        id="CMMC-IA.L2-3.5.1",
        title="Identification",
        description="Identify information system users, processes acting on behalf of users, or devices",
        category="Identification & Authentication",
        testing_procedures=["Identity management review"],
        expected_evidence=["User directory", "Service account inventory"],
    ),
    ComplianceControl(
        id="CMMC-IA.L2-3.5.2",
        title="Authentication",
        description="Authenticate (or verify) the identities of those users, processes, or devices as a prerequisite to allowing access",
        category="Identification & Authentication",
        testing_procedures=["Authentication mechanism review"],
        expected_evidence=["Auth configuration", "Password policy"],
    ),
    ComplianceControl(
        id="CMMC-IA.L2-3.5.3",
        title="Multifactor Authentication",
        description="Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts",
        category="Identification & Authentication",
        testing_procedures=["MFA configuration audit"],
        expected_evidence=["MFA enrollment records", "MFA policy"],
    ),
    # Incident Response (IR)
    ComplianceControl(
        id="CMMC-IR.L2-3.6.1",
        title="Incident Handling",
        description="Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities",
        category="Incident Response",
        testing_procedures=["IR plan review", "Tabletop exercise results"],
        expected_evidence=["Incident response plan", "Exercise after-action reports"],
    ),
    ComplianceControl(
        id="CMMC-IR.L2-3.6.2",
        title="Incident Reporting",
        description="Track, document, and report incidents to appropriate officials and/or authorities both internal and external",
        category="Incident Response",
        testing_procedures=["Incident reporting process review"],
        expected_evidence=["Incident tickets", "Reporting records"],
    ),
    # Maintenance (MA)
    ComplianceControl(
        id="CMMC-MA.L2-3.7.1",
        title="System Maintenance",
        description="Perform maintenance on organizational systems",
        category="Maintenance",
        testing_procedures=["Maintenance schedule review"],
        expected_evidence=["Maintenance logs", "Patch records"],
    ),
    # Media Protection (MP)
    ComplianceControl(
        id="CMMC-MP.L2-3.8.1",
        title="Media Protection",
        description="Protect (i.e., physically control and securely store) information system media containing CUI, both paper and digital",
        category="Media Protection",
        testing_procedures=["Media handling review"],
        expected_evidence=["Media inventory", "Storage security records"],
    ),
    # Risk Assessment (RA)
    ComplianceControl(
        id="CMMC-RA.L2-3.11.1",
        title="Risk Assessment",
        description="Periodically assess the risk to organizational operations, assets, and individuals resulting from the operation of organizational systems and the processing, storage, or transmission of CUI",
        category="Risk Assessment",
        testing_procedures=["Risk assessment review"],
        expected_evidence=["Risk assessment report", "Risk register"],
    ),
    ComplianceControl(
        id="CMMC-RA.L2-3.11.2",
        title="Vulnerability Scanning",
        description="Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified",
        category="Risk Assessment",
        testing_procedures=["Vulnerability scan review"],
        expected_evidence=["Vulnerability scan reports", "Remediation tracking"],
    ),
    # Security Assessment (CA)
    ComplianceControl(
        id="CMMC-CA.L2-3.12.1",
        title="Security Control Assessment",
        description="Periodically assess the security controls in organizational systems to determine if they are effective in their application",
        category="Security Assessment",
        testing_procedures=["Security assessment review"],
        expected_evidence=["Assessment reports", "Control effectiveness matrix"],
    ),
    # System & Communications Protection (SC)
    ComplianceControl(
        id="CMMC-SC.L2-3.13.1",
        title="Boundary Protection",
        description="Monitor, control, and protect organizational communications at the external boundaries and key internal boundaries of the information systems",
        category="System & Comms Protection",
        testing_procedures=["Boundary device review"],
        expected_evidence=["Firewall configurations", "Network diagrams"],
    ),
    ComplianceControl(
        id="CMMC-SC.L2-3.13.8",
        title="CUI Encryption in Transit",
        description="Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission",
        category="System & Comms Protection",
        testing_procedures=["Encryption-in-transit testing"],
        expected_evidence=["TLS configurations", "Certificate inventory"],
    ),
    ComplianceControl(
        id="CMMC-SC.L2-3.13.11",
        title="CUI Encryption at Rest",
        description="Employ FIPS-validated cryptography when used to protect the confidentiality of CUI",
        category="System & Comms Protection",
        testing_procedures=["Encryption-at-rest audit"],
        expected_evidence=["FIPS validation certificates", "Encryption configuration"],
    ),
    # System & Information Integrity (SI)
    ComplianceControl(
        id="CMMC-SI.L2-3.14.1",
        title="Flaw Remediation",
        description="Identify, report, and correct information and information system flaws in a timely manner",
        category="System & Info Integrity",
        testing_procedures=["Patch management review"],
        expected_evidence=["Patch status reports", "Remediation timelines"],
    ),
    ComplianceControl(
        id="CMMC-SI.L2-3.14.2",
        title="Malicious Code Protection",
        description="Provide protection from malicious code at appropriate locations within organizational systems",
        category="System & Info Integrity",
        testing_procedures=["Anti-malware review"],
        expected_evidence=["AV/EDR deployment status", "Malware detection logs"],
    ),
    ComplianceControl(
        id="CMMC-SI.L2-3.14.6",
        title="Security Alerts and Advisories",
        description="Monitor organizational systems including inbound and outbound communications traffic to detect attacks and indicators of potential attacks",
        category="System & Info Integrity",
        testing_procedures=["Monitoring system review"],
        expected_evidence=["IDS/IPS configurations", "Alert records"],
    ),
]

# Keyword → CMMC control ID mapping
_CMMC_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        ["access control", "authorization", "idor", "permissions", "rbac", "least privilege"],
        ["CMMC-AC.L2-3.1.1", "CMMC-AC.L2-3.1.2", "CMMC-AC.L2-3.1.5"],
    ),
    (["privilege escalation", "privesc", "sudo", "root", "admin", "uac"], ["CMMC-AC.L2-3.1.5", "CMMC-AC.L2-3.1.7"]),
    (["remote access", "vpn", "rdp", "ssh", "remote desktop"], ["CMMC-AC.L2-3.1.12"]),
    (["logging", "audit log", "audit trail", "log management", "syslog"], ["CMMC-AU.L2-3.3.1", "CMMC-AU.L2-3.3.2"]),
    (
        ["misconfiguration", "default config", "hardening", "baseline", "configuration"],
        ["CMMC-CM.L2-3.4.1", "CMMC-CM.L2-3.4.2"],
    ),
    (
        ["unnecessary service", "open port", "port scan", "service discovery", "least functionality"],
        ["CMMC-CM.L2-3.4.6"],
    ),
    (
        ["default password", "default credential", "weak password", "password policy", "credential"],
        ["CMMC-IA.L2-3.5.1", "CMMC-IA.L2-3.5.2"],
    ),
    (["mfa", "multi-factor", "two-factor", "2fa", "totp", "authentication"], ["CMMC-IA.L2-3.5.3"]),
    (
        ["incident response", "incident handling", "breach", "containment", "forensic"],
        ["CMMC-IR.L2-3.6.1", "CMMC-IR.L2-3.6.2"],
    ),
    (
        ["vulnerability", "cve-", "unpatched", "outdated", "end of life", "eol", "patch", "flaw"],
        ["CMMC-RA.L2-3.11.2", "CMMC-SI.L2-3.14.1"],
    ),
    (["risk assessment", "risk analysis", "risk management"], ["CMMC-RA.L2-3.11.1"]),
    (["network", "firewall", "boundary", "segmentation", "network security"], ["CMMC-SC.L2-3.13.1"]),
    (
        ["encryption", "tls", "ssl", "cipher", "plaintext", "unencrypted", "certificate", "cryptography"],
        ["CMMC-SC.L2-3.13.8", "CMMC-SC.L2-3.13.11"],
    ),
    (["malware", "trojan", "ransomware", "virus", "backdoor", "webshell", "antivirus"], ["CMMC-SI.L2-3.14.2"]),
    (["monitoring", "siem", "ids", "ips", "anomaly", "detection", "alert"], ["CMMC-SI.L2-3.14.6"]),
    (["sql injection", "xss", "injection", "rce", "ssrf", "csrf", "command injection"], ["CMMC-SI.L2-3.14.1"]),
]


def map_finding_to_cmmc_controls(finding: Finding) -> list[str]:
    """Map a finding to CMMC 2.0 Level 2 control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _CMMC_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
