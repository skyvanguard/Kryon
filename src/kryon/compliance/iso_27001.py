"""ISO 27001:2022 Annex A compliance controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

ISO_27001_CONTROLS: list[ComplianceControl] = [
    # Organizational Controls (A.5)
    ComplianceControl(id="A.5.1", title="Policies for Information Security", description="Information security policy and topic-specific policies shall be defined, approved, and communicated", category="Organizational", testing_procedures=["Policy documentation review"], expected_evidence=["Information security policy", "Policy acknowledgment records"]),
    ComplianceControl(id="A.5.2", title="Information Security Roles and Responsibilities", description="Information security roles and responsibilities shall be defined and allocated", category="Organizational", testing_procedures=["RACI matrix review"], expected_evidence=["Role definitions", "Responsibility assignments"]),
    ComplianceControl(id="A.5.7", title="Threat Intelligence", description="Information relating to information security threats shall be collected and analyzed", category="Organizational", testing_procedures=["Threat intelligence process review"], expected_evidence=["Threat reports", "Intelligence feeds"]),
    ComplianceControl(id="A.5.10", title="Acceptable Use of Information", description="Rules for acceptable use and handling of information assets shall be identified", category="Organizational", testing_procedures=["Acceptable use policy review"], expected_evidence=["AUP documentation", "User acknowledgments"]),
    ComplianceControl(id="A.5.19", title="Information Security in Supplier Relationships", description="Processes and procedures for managing security risks with suppliers shall be established", category="Organizational", testing_procedures=["Supplier security assessment review"], expected_evidence=["Supplier agreements", "Security clauses"]),
    ComplianceControl(id="A.5.23", title="Information Security for Cloud Services", description="Processes for acquisition, use, management, and exit from cloud services shall be established", category="Organizational", testing_procedures=["Cloud security review"], expected_evidence=["Cloud security policy", "Shared responsibility matrix"]),
    ComplianceControl(id="A.5.24", title="Incident Management Planning and Preparation", description="Management responsibilities and procedures for incident response shall be established", category="Organizational", testing_procedures=["IR plan review"], expected_evidence=["Incident response plan", "Contact lists"]),
    ComplianceControl(id="A.5.28", title="Collection of Evidence", description="Procedures for identification, collection, acquisition, and preservation of evidence", category="Organizational", testing_procedures=["Evidence handling review"], expected_evidence=["Chain of custody records", "Forensic procedures"]),
    ComplianceControl(id="A.5.29", title="Information Security During Disruption", description="Organization shall plan how to maintain security during disruptions", category="Organizational", testing_procedures=["BCP/DRP review"], expected_evidence=["Business continuity plan", "DR test results"]),

    # People Controls (A.6)
    ComplianceControl(id="A.6.1", title="Screening", description="Background verification checks on candidates shall be carried out", category="People", testing_procedures=["HR screening process review"], expected_evidence=["Screening policy", "Verification records"]),
    ComplianceControl(id="A.6.3", title="Information Security Awareness", description="Personnel shall receive appropriate awareness training", category="People", testing_procedures=["Training records review"], expected_evidence=["Training materials", "Completion records"]),
    ComplianceControl(id="A.6.5", title="Responsibilities After Termination", description="Responsibilities that remain valid after termination shall be defined and enforced", category="People", testing_procedures=["Offboarding process review"], expected_evidence=["Termination checklist", "NDA records"]),

    # Physical Controls (A.7)
    ComplianceControl(id="A.7.1", title="Physical Security Perimeters", description="Security perimeters shall be defined to protect areas containing sensitive information", category="Physical", testing_procedures=["Physical perimeter assessment"], expected_evidence=["Floor plans", "Access control systems"]),
    ComplianceControl(id="A.7.4", title="Physical Security Monitoring", description="Premises shall be continuously monitored for unauthorized physical access", category="Physical", testing_procedures=["Monitoring system review"], expected_evidence=["CCTV records", "Monitoring logs"]),

    # Technological Controls (A.8)
    ComplianceControl(id="A.8.1", title="User Endpoint Devices", description="Information stored, processed, or accessible via user endpoint devices shall be protected", category="Technological", testing_procedures=["Endpoint security audit"], expected_evidence=["EDR config", "Device management policy"]),
    ComplianceControl(id="A.8.2", title="Privileged Access Rights", description="The allocation and use of privileged access rights shall be restricted and managed", category="Technological", testing_procedures=["Privileged access review"], expected_evidence=["PAM configuration", "Admin account inventory"]),
    ComplianceControl(id="A.8.3", title="Information Access Restriction", description="Access to information shall be restricted in accordance with access control policy", category="Technological", testing_procedures=["Access control testing"], expected_evidence=["ACL configurations", "Access matrix"]),
    ComplianceControl(id="A.8.5", title="Secure Authentication", description="Secure authentication technologies and procedures shall be established", category="Technological", testing_procedures=["Authentication mechanism review"], expected_evidence=["Auth configuration", "MFA enrollment records"]),
    ComplianceControl(id="A.8.7", title="Protection Against Malware", description="Protection against malware shall be implemented and supported by user awareness", category="Technological", testing_procedures=["Anti-malware verification"], expected_evidence=["AV/EDR status", "Malware policy"]),
    ComplianceControl(id="A.8.8", title="Management of Technical Vulnerabilities", description="Information about technical vulnerabilities shall be obtained and appropriate measures taken", category="Technological", testing_procedures=["Vulnerability management review"], expected_evidence=["Vulnerability scan reports", "Patch records"]),
    ComplianceControl(id="A.8.9", title="Configuration Management", description="Configurations including security configurations shall be established and managed", category="Technological", testing_procedures=["Configuration baseline review"], expected_evidence=["Hardening standards", "Configuration audit results"]),
    ComplianceControl(id="A.8.10", title="Information Deletion", description="Information stored in information systems and devices shall be deleted when no longer required", category="Technological", testing_procedures=["Data retention review"], expected_evidence=["Deletion records", "Retention policy"]),
    ComplianceControl(id="A.8.12", title="Data Leakage Prevention", description="Data leakage prevention measures shall be applied to systems containing sensitive data", category="Technological", testing_procedures=["DLP configuration review"], expected_evidence=["DLP policy", "Alert records"]),
    ComplianceControl(id="A.8.15", title="Logging", description="Logs that record activities, exceptions, faults, and other relevant events shall be produced and stored", category="Technological", testing_procedures=["Logging configuration review"], expected_evidence=["Log samples", "Retention configuration"]),
    ComplianceControl(id="A.8.16", title="Monitoring Activities", description="Networks, systems, and applications shall be monitored for anomalous behavior", category="Technological", testing_procedures=["Monitoring system review"], expected_evidence=["SIEM dashboards", "Alert rules"]),
    ComplianceControl(id="A.8.20", title="Networks Security", description="Networks and network devices shall be secured, managed, and controlled", category="Technological", testing_procedures=["Network security assessment"], expected_evidence=["Firewall configs", "Network diagrams"]),
    ComplianceControl(id="A.8.21", title="Security of Network Services", description="Security mechanisms, service levels, and service requirements shall be identified and implemented", category="Technological", testing_procedures=["Network service review"], expected_evidence=["Service agreements", "Network security config"]),
    ComplianceControl(id="A.8.23", title="Web Filtering", description="Access to external websites shall be managed to reduce exposure to malicious content", category="Technological", testing_procedures=["Web filtering review"], expected_evidence=["Proxy configuration", "URL filtering rules"]),
    ComplianceControl(id="A.8.24", title="Use of Cryptography", description="Rules for effective use of cryptography shall be defined and implemented", category="Technological", testing_procedures=["Cryptographic controls review"], expected_evidence=["Encryption standards", "Key management procedures"]),
    ComplianceControl(id="A.8.25", title="Secure Development Life Cycle", description="Rules for secure development of software and systems shall be established", category="Technological", testing_procedures=["SDLC review", "Code review process"], expected_evidence=["SDLC documentation", "SAST/DAST reports"]),
    ComplianceControl(id="A.8.26", title="Application Security Requirements", description="Security requirements shall be identified and specified when developing or acquiring applications", category="Technological", testing_procedures=["Requirements review"], expected_evidence=["Security requirements docs", "Threat models"]),
    ComplianceControl(id="A.8.27", title="Secure System Architecture and Engineering", description="Principles for engineering secure systems shall be established and applied", category="Technological", testing_procedures=["Architecture security review"], expected_evidence=["Architecture diagrams", "Security design docs"]),
    ComplianceControl(id="A.8.28", title="Secure Coding", description="Secure coding principles shall be applied to software development", category="Technological", testing_procedures=["Secure coding standards review", "Code analysis"], expected_evidence=["Coding standards", "Static analysis reports"]),
    ComplianceControl(id="A.8.9b", title="Security Testing in Development and Acceptance", description="Security testing processes shall be defined and implemented in the development life cycle", category="Technological", testing_procedures=["Security test review"], expected_evidence=["Test plans", "DAST/pentest reports"]),
]

# Keyword → ISO 27001 control ID mapping
_ISO_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (["security policy", "information policy", "governance", "policy violation"], ["A.5.1", "A.5.2"]),
    (["threat intel", "threat intelligence", "ioc", "indicator of compromise"], ["A.5.7"]),
    (["supply chain", "supplier", "vendor", "third-party", "third party"], ["A.5.19"]),
    (["cloud", "aws", "azure", "gcp", "s3 bucket", "cloud misconfiguration"], ["A.5.23"]),
    (["incident", "breach", "incident response", "containment", "forensic"], ["A.5.24", "A.5.28"]),
    (["privilege", "admin", "privileged access", "sudo", "root", "escalation"], ["A.8.2"]),
    (["access control", "authorization", "idor", "permissions", "rbac", "authentication"], ["A.8.3", "A.8.5"]),
    (["malware", "trojan", "ransomware", "virus", "backdoor", "webshell"], ["A.8.7"]),
    (["vulnerability", "cve-", "unpatched", "outdated", "end of life", "eol"], ["A.8.8"]),
    (["misconfiguration", "default config", "hardening", "configuration", "baseline"], ["A.8.9"]),
    (["data leak", "data exposure", "sensitive data", "data loss", "dlp"], ["A.8.12"]),
    (["logging", "audit log", "log file", "audit trail", "syslog"], ["A.8.15"]),
    (["monitoring", "siem", "ids", "ips", "anomaly", "detection", "alert"], ["A.8.16"]),
    (["network", "firewall", "port scan", "open port", "segmentation", "vlan"], ["A.8.20", "A.8.21"]),
    (["encryption", "tls", "ssl", "cipher", "certificate", "plaintext", "cryptography"], ["A.8.24"]),
    (["sql injection", "xss", "cross-site", "injection", "rce", "ssrf", "code review", "sast", "dast"], ["A.8.25", "A.8.26", "A.8.28"]),
]


def map_finding_to_iso27001_controls(finding: Finding) -> list[str]:
    """Map a finding to ISO 27001:2022 control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _ISO_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
