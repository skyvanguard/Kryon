"""HIPAA Security Rule (45 CFR §164.3xx) control catalog + finding mapping.

HONEST SCOPE: a scanner only validates the *technical* safeguards (§164.312)
and the technical slice of the administrative safeguards. Process/governance
controls (workforce training, BAAs, contingency planning, physical facility
access) are `verdict_mode="manual"` — they appear in the catalog for coverage
reporting but are NEVER auto-marked PASS/FAIL. Same stance as the CIS
governance safeguards. Do not claim "HIPAA compliant" from this — claim
"technical safeguards mapped".
"""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

FRAMEWORK_NAME = "HIPAA Security Rule"

HIPAA_CONTROLS: list[ComplianceControl] = [
    # --- Technical Safeguards §164.312 (auto — scanner-verifiable) ---
    ComplianceControl(
        id="164.312(a)(1)",
        title="Access Control",
        description="Technical policies limiting ePHI access to authorized persons/software.",
        category="Technical Safeguards",
        testing_procedures=["Access control / authorization testing"],
        expected_evidence=["RBAC config", "authz test results"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.312(a)(2)(iv)",
        title="Encryption and Decryption (at rest)",
        description="Mechanism to encrypt and decrypt ePHI at rest.",
        category="Technical Safeguards",
        testing_procedures=["Encryption-at-rest verification"],
        expected_evidence=["Disk/DB encryption config"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.312(b)",
        title="Audit Controls",
        description="Hardware/software mechanisms that record and examine activity on systems with ePHI.",
        category="Technical Safeguards",
        testing_procedures=["Audit log review"],
        expected_evidence=["Logging config", "audit trail"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.312(c)(1)",
        title="Integrity",
        description="Protect ePHI from improper alteration or destruction.",
        category="Technical Safeguards",
        testing_procedures=["Integrity control review"],
        expected_evidence=["Integrity/checksum controls"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.312(d)",
        title="Person or Entity Authentication",
        description="Verify that a person/entity seeking ePHI access is who they claim.",
        category="Technical Safeguards",
        testing_procedures=["Authentication / MFA / credential testing"],
        expected_evidence=["Auth config", "MFA enforcement"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.312(e)(1)",
        title="Transmission Security",
        description="Guard against unauthorized access to ePHI transmitted over a network.",
        category="Technical Safeguards",
        testing_procedures=["TLS / encryption-in-transit testing"],
        expected_evidence=["TLS config"],
        verdict_mode="auto",
    ),
    # --- Administrative Safeguards §164.308 — technical slice (auto) ---
    ComplianceControl(
        id="164.308(a)(1)(ii)(B)",
        title="Risk Management (vulnerability remediation)",
        description="Implement measures to reduce risks and vulnerabilities to a reasonable level.",
        category="Administrative Safeguards",
        testing_procedures=["Vulnerability scanning"],
        expected_evidence=["Scan reports", "patch status"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.308(a)(5)(ii)(B)",
        title="Protection from Malicious Software",
        description="Procedures for guarding against, detecting, and reporting malicious software.",
        category="Administrative Safeguards",
        testing_procedures=["AV/EDR verification"],
        expected_evidence=["AV/EDR status"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="164.308(a)(6)(ii)",
        title="Response and Reporting (security incidents)",
        description="Identify and respond to suspected or known security incidents.",
        category="Administrative Safeguards",
        testing_procedures=["Incident detection review"],
        expected_evidence=["SIEM / incident logs"],
        verdict_mode="auto",
    ),
    # --- Process / governance (manual — never auto-scored) ---
    ComplianceControl(
        id="164.308(a)(3)(i)",
        title="Workforce Security",
        description="Ensure workforce members have appropriate ePHI access; supervision and clearance procedures.",
        category="Administrative Safeguards",
        testing_procedures=["Interview / policy review"],
        expected_evidence=["Workforce clearance procedures"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="164.308(b)(1)",
        title="Business Associate Contracts",
        description="Written contracts ensuring business associates safeguard ePHI.",
        category="Administrative Safeguards",
        testing_procedures=["Contract review"],
        expected_evidence=["Signed BAAs"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="164.310(a)(1)",
        title="Facility Access Controls",
        description="Limit physical access to systems and the facilities housing them.",
        category="Physical Safeguards",
        testing_procedures=["Physical walkthrough"],
        expected_evidence=["Facility access logs"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="164.310(d)(1)",
        title="Device and Media Controls",
        description="Governs receipt/removal of hardware and media containing ePHI.",
        category="Physical Safeguards",
        testing_procedures=["Media handling review"],
        expected_evidence=["Media disposal records"],
        verdict_mode="manual",
    ),
]

# Only technical controls are keyword-mapped from findings. Process controls
# (verdict_mode="manual") are intentionally absent — a scanner can't verify them.
_HIPAA_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        ["access control", "authorization", "idor", "privilege escalation", "privesc", "broken access"],
        ["164.312(a)(1)"],
    ),
    (
        ["encryption at rest", "unencrypted storage", "plaintext storage", "database not encrypted"],
        ["164.312(a)(2)(iv)"],
    ),
    (["logging", "audit trail", "audit log", "no logging", "monitoring"], ["164.312(b)"]),
    (["integrity", "tampering", "unsigned", "checksum"], ["164.312(c)(1)"]),
    (
        [
            "weak password",
            "default credential",
            "default password",
            "mfa",
            "multi-factor",
            "authentication bypass",
            "brute force",
        ],
        ["164.312(d)"],
    ),
    (
        [
            "weak tls",
            "weak ssl",
            "unencrypted",
            "plaintext",
            "cleartext",
            "expired certificate",
            "insecure transmission",
        ],
        ["164.312(e)(1)"],
    ),
    (["vulnerability", "cve-", "unpatched", "outdated", "end of life", "eol"], ["164.308(a)(1)(ii)(B)"]),
    (["malware", "ransomware", "trojan", "backdoor"], ["164.308(a)(5)(ii)(B)"]),
    (["incident", "breach", "compromise", "intrusion"], ["164.308(a)(6)(ii)"]),
]


def map_finding_to_hipaa_controls(finding: Finding) -> list[str]:
    """Map a finding to HIPAA Security Rule control IDs (technical safeguards only)."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _HIPAA_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
