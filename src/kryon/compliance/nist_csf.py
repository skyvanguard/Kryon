"""NIST Cybersecurity Framework (CSF) 2.0 compliance controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

NIST_CSF_CONTROLS: list[ComplianceControl] = [
    # Govern (GV)
    ComplianceControl(
        id="GV.OC-01",
        title="Organizational Context",
        description="The organizational mission is understood and informs cybersecurity risk management",
        category="Govern",
        testing_procedures=["Review mission-risk alignment documentation"],
        expected_evidence=["Risk management policy", "Mission statement"],
    ),
    ComplianceControl(
        id="GV.OC-02",
        title="Internal and External Stakeholders",
        description="Internal and external stakeholders are identified and their needs understood",
        category="Govern",
        testing_procedures=["Stakeholder inventory review"],
        expected_evidence=["Stakeholder register", "Communication plan"],
    ),
    ComplianceControl(
        id="GV.RM-01",
        title="Risk Management Strategy",
        description="Risk management objectives are established and approved by leadership",
        category="Govern",
        testing_procedures=["Review risk management strategy"],
        expected_evidence=["Risk management strategy document"],
    ),
    ComplianceControl(
        id="GV.RM-02",
        title="Risk Appetite Statement",
        description="Risk appetite and risk tolerance are established and communicated",
        category="Govern",
        testing_procedures=["Review risk appetite documentation"],
        expected_evidence=["Risk appetite statement"],
    ),
    ComplianceControl(
        id="GV.SC-01",
        title="Supply Chain Risk Management",
        description="Cyber supply chain risk management program is established",
        category="Govern",
        testing_procedures=["Review SCRM policy"],
        expected_evidence=["Supply chain risk management policy"],
    ),
    # Identify (ID)
    ComplianceControl(
        id="ID.AM-01",
        title="Asset Inventory — Hardware",
        description="Inventories of hardware managed by the organization are maintained",
        category="Identify",
        testing_procedures=["Asset inventory review"],
        expected_evidence=["Hardware asset inventory", "CMDB export"],
    ),
    ComplianceControl(
        id="ID.AM-02",
        title="Asset Inventory — Software",
        description="Inventories of software and services managed by the organization are maintained",
        category="Identify",
        testing_procedures=["Software inventory review"],
        expected_evidence=["Software inventory", "License records"],
    ),
    ComplianceControl(
        id="ID.AM-07",
        title="Asset Inventory — Data",
        description="Inventories of data and corresponding metadata are maintained",
        category="Identify",
        testing_procedures=["Data classification review"],
        expected_evidence=["Data inventory", "Classification labels"],
    ),
    ComplianceControl(
        id="ID.RA-01",
        title="Vulnerability Identification",
        description="Vulnerabilities in assets are identified, validated, and recorded",
        category="Identify",
        testing_procedures=["Vulnerability scanning", "Penetration testing"],
        expected_evidence=["Vulnerability scan reports", "Pen test findings"],
    ),
    ComplianceControl(
        id="ID.RA-02",
        title="Threat Intelligence",
        description="Cyber threat intelligence is received from information sharing forums and sources",
        category="Identify",
        testing_procedures=["Threat intel feed review"],
        expected_evidence=["Threat intelligence reports", "ISAC membership"],
    ),
    ComplianceControl(
        id="ID.RA-06",
        title="Risk Response",
        description="Risk responses are chosen, prioritized, planned, tracked, and communicated",
        category="Identify",
        testing_procedures=["Risk register review"],
        expected_evidence=["Risk register", "Risk treatment plans"],
    ),
    # Protect (PR)
    ComplianceControl(
        id="PR.AA-01",
        title="Identity Management",
        description="Identities and credentials for authorized users and services are managed",
        category="Protect",
        testing_procedures=["Identity lifecycle review"],
        expected_evidence=["IAM policies", "User provisioning records"],
    ),
    ComplianceControl(
        id="PR.AA-03",
        title="Multi-Factor Authentication",
        description="Users, services, and hardware are authenticated with MFA",
        category="Protect",
        testing_procedures=["MFA configuration audit"],
        expected_evidence=["MFA enrollment records", "Authentication logs"],
    ),
    ComplianceControl(
        id="PR.AA-05",
        title="Access Permissions",
        description="Access permissions, entitlements, and authorizations are defined and enforced",
        category="Protect",
        testing_procedures=["Access control review"],
        expected_evidence=["ACL documentation", "RBAC matrix"],
    ),
    ComplianceControl(
        id="PR.DS-01",
        title="Data-at-Rest Protection",
        description="The confidentiality, integrity, and availability of data-at-rest are protected",
        category="Protect",
        testing_procedures=["Encryption verification"],
        expected_evidence=["Encryption configurations", "Key management records"],
    ),
    ComplianceControl(
        id="PR.DS-02",
        title="Data-in-Transit Protection",
        description="The confidentiality, integrity, and availability of data-in-transit are protected",
        category="Protect",
        testing_procedures=["TLS/SSL testing"],
        expected_evidence=["TLS scan results", "Network encryption config"],
    ),
    ComplianceControl(
        id="PR.PS-01",
        title="Configuration Management",
        description="Configuration management practices are established and applied",
        category="Protect",
        testing_procedures=["Baseline configuration review"],
        expected_evidence=["Hardening guides", "Configuration baselines"],
    ),
    ComplianceControl(
        id="PR.PS-02",
        title="Software Maintenance",
        description="Software is maintained, replaced, and removed commensurate with risk",
        category="Protect",
        testing_procedures=["Patch management review"],
        expected_evidence=["Patch status reports", "EOL tracking"],
    ),
    ComplianceControl(
        id="PR.IR-01",
        title="Incident Response Planning",
        description="Incident response plans are established, maintained, and tested",
        category="Protect",
        testing_procedures=["IR plan review", "Tabletop exercise results"],
        expected_evidence=["Incident response plan", "Exercise reports"],
    ),
    # Detect (DE)
    ComplianceControl(
        id="DE.AE-02",
        title="Anomaly and Event Analysis",
        description="Potentially adverse events are analyzed to better understand associated activities",
        category="Detect",
        testing_procedures=["SIEM rule review", "Alert analysis"],
        expected_evidence=["SIEM configurations", "Alert correlation rules"],
    ),
    ComplianceControl(
        id="DE.AE-06",
        title="Event Correlation",
        description="Information on adverse events is correlated from multiple sources",
        category="Detect",
        testing_procedures=["Log aggregation review"],
        expected_evidence=["Correlation rules", "Data source inventory"],
    ),
    ComplianceControl(
        id="DE.CM-01",
        title="Network Monitoring",
        description="Networks and network services are monitored to find potentially adverse events",
        category="Detect",
        testing_procedures=["IDS/IPS review", "Network monitoring tools"],
        expected_evidence=["IDS/IPS configurations", "Monitoring dashboards"],
    ),
    ComplianceControl(
        id="DE.CM-06",
        title="External Service Provider Monitoring",
        description="External service provider activities are monitored",
        category="Detect",
        testing_procedures=["Third-party monitoring review"],
        expected_evidence=["SLA monitoring records", "Third-party audit reports"],
    ),
    # Respond (RS)
    ComplianceControl(
        id="RS.MA-01",
        title="Incident Management",
        description="The incident response plan is executed in coordination with relevant third parties",
        category="Respond",
        testing_procedures=["Incident report review"],
        expected_evidence=["Incident tickets", "Communication logs"],
    ),
    ComplianceControl(
        id="RS.MA-02",
        title="Incident Triage",
        description="Incidents are categorized and prioritized",
        category="Respond",
        testing_procedures=["Triage process review"],
        expected_evidence=["Incident classification matrix", "Priority assignments"],
    ),
    ComplianceControl(
        id="RS.AN-03",
        title="Incident Analysis",
        description="Analysis is performed to establish what has taken place during an incident",
        category="Respond",
        testing_procedures=["Forensic analysis review"],
        expected_evidence=["Forensic reports", "Timeline analysis"],
    ),
    ComplianceControl(
        id="RS.MI-01",
        title="Incident Mitigation",
        description="Incidents are contained and mitigated",
        category="Respond",
        testing_procedures=["Containment procedure review"],
        expected_evidence=["Containment records", "Mitigation actions"],
    ),
    # Recover (RC)
    ComplianceControl(
        id="RC.RP-01",
        title="Recovery Plan Execution",
        description="The recovery portion of the incident response plan is executed",
        category="Recover",
        testing_procedures=["Recovery procedure review"],
        expected_evidence=["Recovery logs", "System restoration records"],
    ),
    ComplianceControl(
        id="RC.RP-03",
        title="Recovery Verification",
        description="The integrity of backups and restored assets is verified",
        category="Recover",
        testing_procedures=["Backup restoration testing"],
        expected_evidence=["Backup test results", "Integrity check logs"],
    ),
    ComplianceControl(
        id="RC.CO-03",
        title="Recovery Communication",
        description="Recovery activities and progress are communicated to stakeholders",
        category="Recover",
        testing_procedures=["Communication log review"],
        expected_evidence=["Status reports", "Stakeholder notifications"],
    ),
]

# Keyword → NIST CSF control ID mapping
_NIST_CSF_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        ["asset inventory", "hardware inventory", "device inventory", "cmdb", "asset management"],
        ["ID.AM-01", "ID.AM-02"],
    ),
    (
        ["data classification", "data inventory", "sensitive data", "data labeling", "pii", "phi"],
        ["ID.AM-07", "PR.DS-01"],
    ),
    (["vulnerability", "cve-", "vuln scan", "vulnerability scan", "unpatched", "outdated"], ["ID.RA-01", "PR.PS-02"]),
    (["threat intel", "threat intelligence", "ioc", "indicator of compromise", "threat feed"], ["ID.RA-02"]),
    (["risk assessment", "risk analysis", "risk register", "risk management"], ["GV.RM-01", "GV.RM-02", "ID.RA-06"]),
    (["identity", "iam", "user management", "credential", "authentication", "password"], ["PR.AA-01", "PR.AA-05"]),
    (["mfa", "multi-factor", "two-factor", "2fa", "totp"], ["PR.AA-03"]),
    (["encryption", "tls", "ssl", "cipher", "certificate", "plaintext", "unencrypted"], ["PR.DS-01", "PR.DS-02"]),
    (["access control", "authorization", "privilege escalation", "rbac", "permissions", "idor"], ["PR.AA-05"]),
    (["configuration", "hardening", "misconfiguration", "default config", "baseline"], ["PR.PS-01"]),
    (["patch", "update", "end of life", "eol", "deprecated", "old version"], ["PR.PS-02"]),
    (["monitoring", "ids", "ips", "siem", "alert", "detection", "anomaly"], ["DE.AE-02", "DE.CM-01"]),
    (["logging", "audit trail", "audit log", "log management", "event log"], ["DE.AE-06"]),
    (
        ["incident response", "incident handling", "containment", "triage", "forensic"],
        ["PR.IR-01", "RS.MA-01", "RS.MA-02", "RS.AN-03"],
    ),
    (["backup", "recovery", "disaster recovery", "business continuity", "restore"], ["RC.RP-01", "RC.RP-03"]),
    (["supply chain", "third-party", "vendor risk", "third party", "supplier"], ["GV.SC-01", "DE.CM-06"]),
]


def map_finding_to_nist_csf_controls(finding: Finding) -> list[str]:
    """Map a finding to NIST CSF 2.0 control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _NIST_CSF_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
