"""PCI-DSS v4.0 compliance controls and finding mapping."""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

PCI_DSS_V4_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        id="1.1.6",
        title="Documentation of Business Justification",
        description="Justification for all services, protocols, and ports allowed",
        category="Network Security",
        testing_procedures=["Review documentation"],
        expected_evidence=["Network diagram", "Service inventory"],
    ),
    ComplianceControl(
        id="1.2.1",
        title="Inbound and Outbound Traffic Restrictions",
        description="Restrict inbound and outbound traffic to that which is necessary",
        category="Network Security",
        testing_procedures=["Firewall rule review"],
        expected_evidence=["Firewall config"],
    ),
    ComplianceControl(
        id="1.3.1",
        title="Inbound Traffic Restriction to CDE",
        description="Restrict inbound traffic to cardholder data environment",
        category="Network Security",
        testing_procedures=["Firewall testing"],
        expected_evidence=["Segmentation test results"],
    ),
    ComplianceControl(
        id="2.2.2",
        title="Vendor Default Accounts",
        description="Change vendor-supplied defaults before installing on network",
        category="System Configuration",
        testing_procedures=["Credential audit"],
        expected_evidence=["Default password scan results"],
    ),
    ComplianceControl(
        id="2.2.7",
        title="Non-Console Administrative Access Encryption",
        description="Encrypt all non-console administrative access",
        category="System Configuration",
        testing_procedures=["Protocol analysis"],
        expected_evidence=["SSH/TLS config"],
    ),
    ComplianceControl(
        id="3.4.1",
        title="PAN Rendering Unreadable",
        description="Render PAN unreadable anywhere it is stored",
        category="Data Protection",
        testing_procedures=["Data storage review"],
        expected_evidence=["Encryption config"],
    ),
    ComplianceControl(
        id="3.5.1",
        title="Stored Account Data Protection",
        description="Protect stored account data with strong cryptography",
        category="Data Protection",
        testing_procedures=["Encryption verification"],
        expected_evidence=["Key management docs"],
    ),
    ComplianceControl(
        id="4.2.1",
        title="Strong Cryptography for Transmission",
        description="Strong cryptography for transmission of cardholder data",
        category="Encryption",
        testing_procedures=["TLS testing"],
        expected_evidence=["SSL/TLS scan results"],
    ),
    ComplianceControl(
        id="4.2.2",
        title="Certificate Validation",
        description="Certificates used for PAN transmissions over open networks are confirmed valid",
        category="Encryption",
        testing_procedures=["Certificate review"],
        expected_evidence=["Certificate chain"],
    ),
    ComplianceControl(
        id="5.2.1",
        title="Anti-Malware Deployed",
        description="Anti-malware solution deployed on all applicable systems",
        category="Malware Protection",
        testing_procedures=["AV verification"],
        expected_evidence=["AV status report"],
    ),
    ComplianceControl(
        id="6.2.4",
        title="Software Engineering Techniques",
        description="Address common software vulnerabilities in development",
        category="Application Security",
        testing_procedures=["Code review", "SAST/DAST"],
        expected_evidence=["Scan results"],
    ),
    ComplianceControl(
        id="6.3.1",
        title="Vulnerability Identification",
        description="Identify and manage security vulnerabilities",
        category="Vulnerability Management",
        testing_procedures=["Vulnerability scanning"],
        expected_evidence=["Vuln scan reports"],
    ),
    ComplianceControl(
        id="6.3.3",
        title="Critical Security Patches",
        description="Install critical security patches within one month",
        category="Vulnerability Management",
        testing_procedures=["Patch status review"],
        expected_evidence=["Patch report"],
    ),
    ComplianceControl(
        id="6.4.1",
        title="Public-Facing Web Application Protection",
        description="Protect public-facing web applications against attacks",
        category="Application Security",
        testing_procedures=["WAF testing", "Pen test"],
        expected_evidence=["WAF config", "Pen test report"],
    ),
    ComplianceControl(
        id="7.2.1",
        title="Access Control Based on Need-to-Know",
        description="Appropriate access based on business need-to-know",
        category="Access Control",
        testing_procedures=["Access review"],
        expected_evidence=["ACL documentation"],
    ),
    ComplianceControl(
        id="7.2.2",
        title="Access Assigned Based on Job Function",
        description="Access assigned based on job classification and function",
        category="Access Control",
        testing_procedures=["Role review"],
        expected_evidence=["Role matrix"],
    ),
    ComplianceControl(
        id="8.3.4",
        title="Account Lockout",
        description="Account lockout after invalid authentication attempts",
        category="Authentication",
        testing_procedures=["Lockout testing"],
        expected_evidence=["Auth config"],
    ),
    ComplianceControl(
        id="8.3.6",
        title="Password Complexity",
        description="Minimum password complexity requirements",
        category="Authentication",
        testing_procedures=["Password policy review"],
        expected_evidence=["Policy config"],
    ),
    ComplianceControl(
        id="8.4.2",
        title="MFA for CDE Access",
        description="MFA for all access into the cardholder data environment",
        category="Authentication",
        testing_procedures=["MFA verification"],
        expected_evidence=["MFA config"],
    ),
    ComplianceControl(
        id="10.2.1",
        title="Audit Trails",
        description="Audit trails for all access to cardholder data",
        category="Logging & Monitoring",
        testing_procedures=["Log review"],
        expected_evidence=["Log samples"],
    ),
    ComplianceControl(
        id="10.4.1",
        title="Audit Log Review",
        description="Review audit logs at least daily",
        category="Logging & Monitoring",
        testing_procedures=["Process review"],
        expected_evidence=["Review schedule"],
    ),
    ComplianceControl(
        id="11.3.1",
        title="Internal Vulnerability Scanning",
        description="Internal vulnerability scanning at least quarterly",
        category="Testing",
        testing_procedures=["Scan schedule review"],
        expected_evidence=["Scan reports"],
    ),
    ComplianceControl(
        id="11.3.2",
        title="External Vulnerability Scanning",
        description="External vulnerability scanning at least quarterly by PCI ASV",
        category="Testing",
        testing_procedures=["ASV scan review"],
        expected_evidence=["ASV reports"],
    ),
    ComplianceControl(
        id="11.4.1",
        title="Penetration Testing",
        description="External and internal penetration testing at least annually",
        category="Testing",
        testing_procedures=["Pen test review"],
        expected_evidence=["Pen test report"],
    ),
    ComplianceControl(
        id="12.3.1",
        title="Risk Assessment",
        description="Formal risk assessment at least annually",
        category="Policy",
        testing_procedures=["Risk assessment review"],
        expected_evidence=["Risk assessment doc"],
    ),
]

# Controls Kryon assesses DETERMINISTICALLY (a real check produces a PASS/FAIL).
# Everything else requires documentary/interview evidence (network diagrams,
# pen-test reports, risk assessments, access reviews) and is reported MANUAL —
# NEVER an automatic PASS. Being explicit here is what makes the PCI report
# honest instead of looking like a scanner that "covered everything".
PCI_AUTO_CONTROLS: frozenset[str] = frozenset(
    {
        "1.2.1",  # inbound/outbound restrictions — derivable from port scan
        "1.3.1",  # inbound to CDE — segmentation probe
        "2.2.2",  # vendor default accounts — credential check
        "2.2.7",  # non-console admin encryption — SSH/TLS check
        "4.2.1",  # strong crypto in transit — TLS scan
        "4.2.2",  # certificate validation — cert chain check
        "5.2.1",  # anti-malware deployed — process/service check
        "6.3.1",  # vulnerability identification — vuln scan
        "6.3.3",  # critical security patches — patch/version check
        "8.3.4",  # account lockout — auth config check
        "8.3.6",  # password complexity — policy check
        "8.4.2",  # MFA for CDE — MFA config check
        "10.2.1",  # audit trails — logging check
    }
)

# Apply the classification to the catalog so the runner/report honours it: AUTO
# controls can yield a deterministic verdict; the rest stay MANUAL.
for _control in PCI_DSS_V4_CONTROLS:
    try:
        _control.verdict_mode = "auto" if _control.id in PCI_AUTO_CONTROLS else "manual"
    except (AttributeError, TypeError):  # frozen model — classification via helpers below
        pass


def pci_assessment_type(control_id: str) -> str:
    """``"AUTO"`` if Kryon has a deterministic check for this control, else
    ``"MANUAL"`` (requires documentary/interview evidence)."""
    return "AUTO" if control_id in PCI_AUTO_CONTROLS else "MANUAL"


def pci_coverage_summary() -> dict[str, object]:
    """Honest PCI coverage breakdown for the report and for operators."""
    auto = [c.id for c in PCI_DSS_V4_CONTROLS if c.id in PCI_AUTO_CONTROLS]
    manual = [c.id for c in PCI_DSS_V4_CONTROLS if c.id not in PCI_AUTO_CONTROLS]
    total = len(PCI_DSS_V4_CONTROLS)
    return {
        "total": total,
        "auto": len(auto),
        "manual": len(manual),
        "auto_pct": round(100 * len(auto) / total, 1) if total else 0.0,
        "auto_ids": auto,
        "manual_ids": manual,
    }


# Keyword → PCI control ID mapping
_PCI_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (["open port", "service discovery", "port scan", "unnecessary service"], ["1.1.6", "1.2.1"]),
    (["default password", "default credential", "vendor default"], ["2.2.2"]),
    (["unencrypted", "plaintext", "http://", "telnet", "ftp"], ["2.2.7", "4.2.1"]),
    (["data exposure", "pan ", "card number", "sensitive data"], ["3.4.1", "3.5.1"]),
    (["weak ssl", "weak tls", "certificate", "weak cipher", "expired cert"], ["4.2.1", "4.2.2"]),
    (["malware", "trojan", "ransomware", "virus"], ["5.2.1"]),
    (["rdp exposed", "smb exposed", "exposed database", "redis", "mongodb", "elasticsearch open"], ["1.2.1"]),
    (
        [
            "sql injection",
            "xss",
            "cross-site",
            "injection",
            "ssrf",
            "csrf",
            "rce",
            "lfi",
            "rfi",
            "file upload",
            "command injection",
        ],
        ["6.2.4"],
    ),
    (["outdated", "unpatched", "old version", "end of life", "eol", "cve-"], ["6.3.1", "6.3.3"]),
    (["waf", "web application firewall"], ["6.4.1"]),
    (["access control", "authorization", "idor", "privilege escalation", "privesc"], ["7.2.1", "7.2.2"]),
    (["brute force", "credential stuffing", "account lockout"], ["8.3.4"]),
    (["weak password", "password policy", "password strength"], ["8.3.6"]),
    (["mfa", "multi-factor", "two-factor", "2fa"], ["8.4.2"]),
    (["logging", "audit trail", "log file", "audit log"], ["10.2.1", "10.4.1"]),
    (["vulnerability scan", "vuln scan"], ["11.3.1", "11.3.2"]),
    (["penetration test", "pen test", "pentest"], ["11.4.1"]),
]


def map_finding_to_pci_controls(finding: Finding) -> list[str]:
    """Map a finding to PCI-DSS control IDs."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _PCI_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
