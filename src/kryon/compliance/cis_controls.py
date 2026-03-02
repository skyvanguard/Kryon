"""CIS Controls v8 (Implementation Groups 1-2) compliance controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

CIS_CONTROLS: list[ComplianceControl] = [
    # CIS Control 1: Inventory and Control of Enterprise Assets
    ComplianceControl(
        id="CIS-1.1",
        title="Establish and Maintain Detailed Enterprise Asset Inventory",
        description="Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data",
        category="Inventory & Control of Assets",
        testing_procedures=["Asset inventory review"],
        expected_evidence=["Asset inventory database", "Discovery scan results"],
    ),
    ComplianceControl(
        id="CIS-1.2",
        title="Address Unauthorized Assets",
        description="Ensure that a process exists to address unauthorized assets on a weekly basis",
        category="Inventory & Control of Assets",
        testing_procedures=["Rogue device detection review"],
        expected_evidence=["NAC logs", "Unauthorized asset reports"],
    ),
    # CIS Control 2: Inventory and Control of Software Assets
    ComplianceControl(
        id="CIS-2.1",
        title="Establish and Maintain a Software Inventory",
        description="Establish and maintain a detailed inventory of all licensed and authorized software installed on enterprise assets",
        category="Software Inventory",
        testing_procedures=["Software inventory review"],
        expected_evidence=["Software inventory", "License records"],
    ),
    ComplianceControl(
        id="CIS-2.3",
        title="Address Unauthorized Software",
        description="Ensure that unauthorized software is either removed or the inventory is updated on a weekly basis",
        category="Software Inventory",
        testing_procedures=["Application whitelisting review"],
        expected_evidence=["Application control logs", "Removal records"],
    ),
    # CIS Control 3: Data Protection
    ComplianceControl(
        id="CIS-3.1",
        title="Establish and Maintain a Data Management Process",
        description="Establish and maintain a data management process covering sensitivity and handling of enterprise data",
        category="Data Protection",
        testing_procedures=["Data classification review"],
        expected_evidence=["Data classification policy", "Data inventory"],
    ),
    ComplianceControl(
        id="CIS-3.10",
        title="Encrypt Sensitive Data in Transit",
        description="Encrypt sensitive data in transit using current encryption standards",
        category="Data Protection",
        testing_procedures=["TLS/SSL testing"],
        expected_evidence=["TLS scan results", "Encryption configuration"],
    ),
    ComplianceControl(
        id="CIS-3.11",
        title="Encrypt Sensitive Data at Rest",
        description="Encrypt sensitive data at rest on servers, applications, and databases with current encryption standards",
        category="Data Protection",
        testing_procedures=["Encryption-at-rest audit"],
        expected_evidence=["Encryption configs", "Key management records"],
    ),
    # CIS Control 4: Secure Configuration of Enterprise Assets and Software
    ComplianceControl(
        id="CIS-4.1",
        title="Establish and Maintain a Secure Configuration Process",
        description="Establish and maintain a secure configuration process for enterprise assets and software",
        category="Secure Configuration",
        testing_procedures=["Configuration baseline review"],
        expected_evidence=["Hardening standards", "Baseline configurations"],
    ),
    ComplianceControl(
        id="CIS-4.7",
        title="Manage Default Accounts on Enterprise Assets and Software",
        description="Manage default accounts on enterprise assets and software including changing defaults or disabling them",
        category="Secure Configuration",
        testing_procedures=["Default account audit"],
        expected_evidence=["Account audit results", "Default credential scan"],
    ),
    # CIS Control 5: Account Management
    ComplianceControl(
        id="CIS-5.1",
        title="Establish and Maintain an Account Inventory",
        description="Establish and maintain an inventory of all accounts managed in the enterprise",
        category="Account Management",
        testing_procedures=["Account inventory review"],
        expected_evidence=["Account inventory", "Privileged account list"],
    ),
    ComplianceControl(
        id="CIS-5.4",
        title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
        description="Restrict administrator privileges to dedicated administrator accounts on enterprise assets",
        category="Account Management",
        testing_procedures=["Privileged access review"],
        expected_evidence=["Admin account inventory", "PAM configuration"],
    ),
    # CIS Control 6: Access Control Management
    ComplianceControl(
        id="CIS-6.1",
        title="Establish an Access Granting Process",
        description="Establish and follow a process to grant access to enterprise assets and software based on need-to-know",
        category="Access Control",
        testing_procedures=["Access provisioning review"],
        expected_evidence=["Access request records", "Approval workflows"],
    ),
    ComplianceControl(
        id="CIS-6.3",
        title="Require MFA for Externally Exposed Applications",
        description="Require all externally exposed enterprise or third-party applications to enforce MFA",
        category="Access Control",
        testing_procedures=["MFA configuration review"],
        expected_evidence=["MFA enrollment records", "Application auth config"],
    ),
    ComplianceControl(
        id="CIS-6.5",
        title="Require MFA for Administrative Access",
        description="Require MFA for all administrative access accounts",
        category="Access Control",
        testing_procedures=["Admin MFA audit"],
        expected_evidence=["MFA configuration for admin accounts"],
    ),
    # CIS Control 7: Continuous Vulnerability Management
    ComplianceControl(
        id="CIS-7.1",
        title="Establish and Maintain a Vulnerability Management Process",
        description="Establish and maintain a documented vulnerability management process for enterprise assets",
        category="Vulnerability Management",
        testing_procedures=["Vulnerability management review"],
        expected_evidence=["VM policy", "Scan schedules"],
    ),
    ComplianceControl(
        id="CIS-7.4",
        title="Perform Automated Application Patch Management",
        description="Perform application updates on enterprise assets through automated patch management on a monthly or more frequent basis",
        category="Vulnerability Management",
        testing_procedures=["Patch management review"],
        expected_evidence=["Patch status reports", "Automated patching config"],
    ),
    # CIS Control 8: Audit Log Management
    ComplianceControl(
        id="CIS-8.1",
        title="Establish and Maintain an Audit Log Management Process",
        description="Establish and maintain an audit log management process for enterprise assets",
        category="Audit Log Management",
        testing_procedures=["Log management review"],
        expected_evidence=["Log management policy", "Log configuration"],
    ),
    ComplianceControl(
        id="CIS-8.5",
        title="Collect Detailed Audit Logs",
        description="Configure detailed audit logging for enterprise assets containing sensitive data",
        category="Audit Log Management",
        testing_procedures=["Audit log configuration review"],
        expected_evidence=["Log samples", "Configuration records"],
    ),
    # CIS Control 9: Email and Web Browser Protections
    ComplianceControl(
        id="CIS-9.1",
        title="Ensure Use of Only Fully Supported Browsers and Email Clients",
        description="Ensure only fully supported browsers and email clients are allowed to execute",
        category="Email & Web Protection",
        testing_procedures=["Browser/email client inventory"],
        expected_evidence=["Supported software list", "Version audit"],
    ),
    # CIS Control 10: Malware Defenses
    ComplianceControl(
        id="CIS-10.1",
        title="Deploy and Maintain Anti-Malware Software",
        description="Deploy and maintain anti-malware software on all enterprise assets",
        category="Malware Defenses",
        testing_procedures=["Anti-malware deployment review"],
        expected_evidence=["AV/EDR deployment status", "Update records"],
    ),
    # CIS Control 11: Data Recovery
    ComplianceControl(
        id="CIS-11.1",
        title="Establish and Maintain a Data Recovery Process",
        description="Establish and maintain a data recovery process covering enterprise assets",
        category="Data Recovery",
        testing_procedures=["Backup and recovery review"],
        expected_evidence=["Backup policy", "Recovery test results"],
    ),
    # CIS Control 12: Network Infrastructure Management
    ComplianceControl(
        id="CIS-12.1",
        title="Ensure Network Infrastructure Is Up-to-Date",
        description="Ensure network infrastructure is kept up-to-date with at least latest security patches",
        category="Network Infrastructure",
        testing_procedures=["Network device patch review"],
        expected_evidence=["Network device inventory", "Firmware versions"],
    ),
    # CIS Control 13: Network Monitoring and Defense
    ComplianceControl(
        id="CIS-13.1",
        title="Centralize Security Event Alerting",
        description="Centralize security event alerting across enterprise assets for log correlation and analysis",
        category="Network Monitoring",
        testing_procedures=["SIEM deployment review"],
        expected_evidence=["SIEM configuration", "Log source inventory"],
    ),
    # CIS Control 14: Security Awareness and Skills Training
    ComplianceControl(
        id="CIS-14.1",
        title="Establish and Maintain a Security Awareness Program",
        description="Establish and maintain a security awareness program addressing phishing, social engineering, and authentication",
        category="Security Awareness",
        testing_procedures=["Awareness programme review"],
        expected_evidence=["Training materials", "Completion records"],
    ),
    # CIS Control 16: Application Software Security
    ComplianceControl(
        id="CIS-16.1",
        title="Establish and Maintain a Secure Application Development Process",
        description="Establish and maintain a secure application development process addressing design, coding, and testing",
        category="Application Security",
        testing_procedures=["SDLC security review"],
        expected_evidence=["Secure SDLC policy", "SAST/DAST results"],
    ),
    # CIS Control 17: Incident Response Management
    ComplianceControl(
        id="CIS-17.1",
        title="Designate Personnel to Manage Incident Handling",
        description="Designate one key person and at least one backup to manage the incident handling process",
        category="Incident Response",
        testing_procedures=["IR team review"],
        expected_evidence=["IR team roster", "Contact information"],
    ),
    # CIS Control 18: Penetration Testing
    ComplianceControl(
        id="CIS-18.1",
        title="Establish and Maintain a Penetration Testing Program",
        description="Establish and maintain a penetration testing program appropriate to the size, complexity, and maturity of the enterprise",
        category="Penetration Testing",
        testing_procedures=["Pen test program review"],
        expected_evidence=["Pen test policy", "Test schedule"],
    ),
]

# Keyword → CIS Controls v8 control ID mapping
_CIS_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        ["asset inventory", "hardware inventory", "device inventory", "asset management", "cmdb", "rogue device"],
        ["CIS-1.1", "CIS-1.2"],
    ),
    (["software inventory", "unauthorized software", "application control", "shadow it"], ["CIS-2.1", "CIS-2.3"]),
    (["data classification", "sensitive data", "data exposure", "pii", "data leak", "dlp"], ["CIS-3.1"]),
    (
        ["encryption", "tls", "ssl", "plaintext", "unencrypted", "cipher", "certificate", "https"],
        ["CIS-3.10", "CIS-3.11"],
    ),
    (
        ["misconfiguration", "default password", "default credential", "hardening", "configuration", "baseline"],
        ["CIS-4.1", "CIS-4.7"],
    ),
    (["privilege", "admin", "root", "sudo", "privileged access", "escalation", "pam"], ["CIS-5.4", "CIS-6.1"]),
    (["mfa", "multi-factor", "two-factor", "2fa", "authentication"], ["CIS-6.3", "CIS-6.5"]),
    (["access control", "authorization", "idor", "permissions", "rbac"], ["CIS-6.1"]),
    (["vulnerability", "cve-", "unpatched", "outdated", "end of life", "eol", "patch"], ["CIS-7.1", "CIS-7.4"]),
    (["logging", "audit log", "log management", "audit trail", "syslog"], ["CIS-8.1", "CIS-8.5"]),
    (["malware", "trojan", "ransomware", "virus", "backdoor", "webshell", "antivirus"], ["CIS-10.1"]),
    (["backup", "recovery", "disaster recovery", "restore", "data recovery"], ["CIS-11.1"]),
    (["network", "firewall", "open port", "port scan", "segmentation", "network device"], ["CIS-12.1"]),
    (["monitoring", "siem", "ids", "ips", "anomaly", "detection", "alert"], ["CIS-13.1"]),
    (["sql injection", "xss", "injection", "rce", "ssrf", "csrf", "code review", "sast", "dast"], ["CIS-16.1"]),
    (["incident response", "incident handling", "breach", "containment"], ["CIS-17.1"]),
    (["penetration test", "pen test", "pentest", "red team"], ["CIS-18.1"]),
]


def map_finding_to_cis_controls(finding: Finding) -> list[str]:
    """Map a finding to CIS Controls v8 control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _CIS_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
