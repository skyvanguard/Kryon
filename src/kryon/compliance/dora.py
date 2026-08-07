"""DORA (Digital Operational Resilience Act) compliance controls and finding mapping.

Regulation (EU) 2022/2554 — in force since 17 Jan 2025 (together with its RTS/ITS).
Current and applicable as of 2026-07; a regulation, not a versioned standard.
"""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

DORA_CONTROLS: list[ComplianceControl] = [
    # ICT Risk Management (Chapter II, Articles 5-16)
    ComplianceControl(
        id="DORA-5.1",
        title="ICT Risk Management Framework",
        description="Financial entities shall have a sound, comprehensive, and well-documented ICT risk management framework",
        category="ICT Risk Management",
        testing_procedures=["Framework documentation review"],
        expected_evidence=["ICT risk management framework", "Board approval records"],
    ),
    ComplianceControl(
        id="DORA-5.2",
        title="Management Body Responsibility",
        description="The management body shall define, approve, oversee, and be accountable for the ICT risk management framework",
        category="ICT Risk Management",
        testing_procedures=["Governance structure review"],
        expected_evidence=["Board minutes", "Accountability matrix"],
    ),
    ComplianceControl(
        id="DORA-6.1",
        title="ICT Systems, Protocols, and Tools",
        description="Financial entities shall use and maintain updated ICT systems, protocols, and tools that are appropriate, reliable, and have sufficient capacity",
        category="ICT Risk Management",
        testing_procedures=["ICT asset inventory review", "Capacity assessment"],
        expected_evidence=["Asset inventory", "Capacity reports"],
    ),
    ComplianceControl(
        id="DORA-6.2",
        title="ICT System Identification",
        description="Identify, classify, and adequately document all ICT supported business functions, information assets, and ICT assets",
        category="ICT Risk Management",
        testing_procedures=["Asset classification review"],
        expected_evidence=["ICT asset register", "Classification matrix"],
    ),
    ComplianceControl(
        id="DORA-7.1",
        title="ICT Threat Detection",
        description="Identify all sources of ICT risk, including ICT-related dependencies on third-party service providers",
        category="ICT Risk Management",
        testing_procedures=["Threat assessment review"],
        expected_evidence=["Threat register", "Dependency map"],
    ),
    ComplianceControl(
        id="DORA-8.1",
        title="Protection and Prevention",
        description="Implement ICT security policies, procedures, protocols, and tools for protection and prevention of ICT risk",
        category="ICT Risk Management",
        testing_procedures=["Security controls assessment"],
        expected_evidence=["Security policies", "Control configurations"],
    ),
    ComplianceControl(
        id="DORA-8.2",
        title="Network Security Management",
        description="Design the network connection infrastructure to enable instant severing to minimize and prevent contagion",
        category="ICT Risk Management",
        testing_procedures=["Network architecture review"],
        expected_evidence=["Network diagrams", "Segmentation configs"],
    ),
    ComplianceControl(
        id="DORA-8.3",
        title="Encryption and Cryptographic Controls",
        description="Implement policies and procedures on cryptographic controls including encryption of data in transit and at rest",
        category="ICT Risk Management",
        testing_procedures=["Encryption assessment"],
        expected_evidence=["Encryption policies", "Key management procedures"],
    ),
    ComplianceControl(
        id="DORA-9.1",
        title="Detection Capabilities",
        description="Mechanisms to promptly detect anomalous activities, ICT network performance issues, and ICT-related incidents",
        category="ICT Risk Management",
        testing_procedures=["Detection capability review"],
        expected_evidence=["SIEM configuration", "Alert rules"],
    ),
    ComplianceControl(
        id="DORA-9.2",
        title="Detection Testing",
        description="Regular testing of ICT detection mechanisms including alert thresholds and response procedures",
        category="ICT Risk Management",
        testing_procedures=["Detection testing review"],
        expected_evidence=["Test results", "Alert tuning records"],
    ),
    ComplianceControl(
        id="DORA-10.1",
        title="ICT Business Continuity Policy",
        description="Comprehensive ICT business continuity policy as an integral part of the operational business continuity policy",
        category="ICT Risk Management",
        testing_procedures=["BCP review"],
        expected_evidence=["ICT BCP document", "Recovery objectives"],
    ),
    ComplianceControl(
        id="DORA-11.1",
        title="ICT Response and Recovery Plans",
        description="ICT response and recovery plans shall be put in place and regularly tested",
        category="ICT Risk Management",
        testing_procedures=["Recovery plan review", "DR test results"],
        expected_evidence=["Recovery plans", "Test reports"],
    ),
    ComplianceControl(
        id="DORA-12.1",
        title="Backup Policies and Procedures",
        description="Policies and procedures for backup including scope, frequency, and restoration methods",
        category="ICT Risk Management",
        testing_procedures=["Backup policy review", "Restoration testing"],
        expected_evidence=["Backup policy", "Restoration test records"],
    ),
    # Incident Reporting (Chapter III, Articles 17-23)
    ComplianceControl(
        id="DORA-17.1",
        title="ICT-Related Incident Management",
        description="Define, establish, and implement an ICT-related incident management process to detect, manage, and notify ICT-related incidents",
        category="Incident Reporting",
        testing_procedures=["Incident management process review"],
        expected_evidence=["Incident management policy", "Incident classification matrix"],
    ),
    ComplianceControl(
        id="DORA-17.2",
        title="Incident Classification",
        description="Classify ICT-related incidents according to criteria including number of clients affected, duration, and geographical spread",
        category="Incident Reporting",
        testing_procedures=["Classification criteria review"],
        expected_evidence=["Classification scheme", "Incident records"],
    ),
    ComplianceControl(
        id="DORA-19.1",
        title="Major Incident Reporting",
        description="Report major ICT-related incidents to the relevant competent authority",
        category="Incident Reporting",
        testing_procedures=["Reporting process review"],
        expected_evidence=["Incident notification templates", "Reporting timelines"],
    ),
    # Digital Operational Resilience Testing (Chapter IV, Articles 24-27)
    ComplianceControl(
        id="DORA-24.1",
        title="General Requirements for Testing",
        description="Establish, maintain, and review a digital operational resilience testing programme",
        category="Resilience Testing",
        testing_procedures=["Testing programme review"],
        expected_evidence=["Testing programme document", "Test schedules"],
    ),
    ComplianceControl(
        id="DORA-25.1",
        title="Testing of ICT Tools and Systems",
        description="Conduct appropriate testing of ICT tools and systems including vulnerability assessments, network security, and penetration testing",
        category="Resilience Testing",
        testing_procedures=["Testing results review"],
        expected_evidence=["Vulnerability scan reports", "Penetration test reports"],
    ),
    ComplianceControl(
        id="DORA-26.1",
        title="Threat-Led Penetration Testing (TLPT)",
        description="Carry out advanced testing through TLPT at least every three years",
        category="Resilience Testing",
        testing_procedures=["TLPT report review"],
        expected_evidence=["TLPT reports", "Red team findings"],
    ),
    # Third-Party Risk (Chapter V, Articles 28-44)
    ComplianceControl(
        id="DORA-28.1",
        title="Third-Party ICT Risk Management",
        description="Manage ICT third-party risk as an integral component of ICT risk within the ICT risk management framework",
        category="Third-Party Risk",
        testing_procedures=["Third-party risk management review"],
        expected_evidence=["Third-party register", "Risk assessments"],
    ),
    ComplianceControl(
        id="DORA-28.2",
        title="Third-Party Due Diligence",
        description="Conduct due diligence before entering into contractual arrangements with ICT third-party service providers",
        category="Third-Party Risk",
        testing_procedures=["Due diligence process review"],
        expected_evidence=["Due diligence reports", "Vendor assessments"],
    ),
]

# Keyword → DORA control ID mapping
_DORA_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (["risk management", "risk framework", "risk assessment", "ict risk"], ["DORA-5.1", "DORA-5.2"]),
    (["asset inventory", "ict asset", "system inventory", "asset management", "cmdb"], ["DORA-6.1", "DORA-6.2"]),
    (["threat detection", "threat assessment", "threat modeling", "threat source"], ["DORA-7.1"]),
    (["security policy", "security control", "access control", "authentication", "authorization"], ["DORA-8.1"]),
    (["network security", "segmentation", "firewall", "network isolation", "open port", "port scan"], ["DORA-8.2"]),
    (["encryption", "tls", "ssl", "cipher", "plaintext", "unencrypted", "cryptography", "certificate"], ["DORA-8.3"]),
    (["monitoring", "siem", "ids", "ips", "anomaly detection", "alert", "detection"], ["DORA-9.1", "DORA-9.2"]),
    (
        ["business continuity", "disaster recovery", "backup", "restore", "recovery"],
        ["DORA-10.1", "DORA-11.1", "DORA-12.1"],
    ),
    (["incident response", "incident management", "breach", "incident handling"], ["DORA-17.1", "DORA-17.2"]),
    (["major incident", "critical incident", "incident notification", "incident report"], ["DORA-19.1"]),
    (["vulnerability scan", "penetration test", "pentest", "pen test", "security testing"], ["DORA-24.1", "DORA-25.1"]),
    (["red team", "threat-led", "tlpt", "adversary simulation", "purple team"], ["DORA-26.1"]),
    (["third-party", "third party", "vendor", "supplier", "outsourcing", "cloud provider"], ["DORA-28.1", "DORA-28.2"]),
    (["vulnerability", "cve-", "unpatched", "outdated", "end of life", "eol"], ["DORA-25.1", "DORA-8.1"]),
    (["malware", "ransomware", "trojan", "backdoor"], ["DORA-8.1", "DORA-9.1"]),
]


def map_finding_to_dora_controls(finding: Finding) -> list[str]:
    """Map a finding to DORA control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _DORA_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
