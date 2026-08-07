"""GDPR (Regulation 2016/679) control catalog + finding mapping.

HONEST SCOPE: a scanner only touches the *technical* security measures —
essentially Art. 32 (security of processing), Art. 5(1)(f), Art. 25
(security by design) and Art. 33 (breach detection). The bulk of GDPR is
process/legal (lawful basis, consent, data-subject rights, DPO, records of
processing) and is `verdict_mode="manual"` — catalogued for coverage but
NEVER auto-scored. Do not claim "GDPR compliant" from findings — claim
"technical security measures (Art. 32) mapped".
"""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

FRAMEWORK_NAME = "GDPR"

GDPR_CONTROLS: list[ComplianceControl] = [
    # --- Art. 32 Security of processing (auto — scanner-verifiable) ---
    ComplianceControl(
        id="Art.32(1)(a)",
        title="Pseudonymisation and Encryption",
        description="Encryption/pseudonymisation of personal data, at rest and in transit.",
        category="Security of processing",
        testing_procedures=["Encryption (TLS + at-rest) verification"],
        expected_evidence=["TLS config", "at-rest encryption"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="Art.32(1)(b)",
        title="Confidentiality, Integrity, Availability, Resilience",
        description="Ensure ongoing confidentiality, integrity, availability and resilience of processing systems.",
        category="Security of processing",
        testing_procedures=["Access control + hardening review"],
        expected_evidence=["Access controls", "hardening config"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="Art.32(1)(c)",
        title="Restore Availability",
        description="Ability to restore availability and access to personal data after an incident.",
        category="Security of processing",
        testing_procedures=["Backup / recovery review"],
        expected_evidence=["Backup + DR evidence"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="Art.32(1)(d)",
        title="Testing and Evaluation of Effectiveness",
        description="Regular testing/assessing of technical and organisational security measures.",
        category="Security of processing",
        testing_procedures=["Vulnerability scanning / pentest"],
        expected_evidence=["Scan/pentest reports"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="Art.5(1)(f)",
        title="Integrity and Confidentiality",
        description="Personal data processed with appropriate security against unauthorised processing/loss.",
        category="Principles",
        testing_procedures=["Data-exposure review"],
        expected_evidence=["No sensitive-data exposure"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="Art.25",
        title="Data Protection by Design and by Default",
        description="Technical measures embedding data protection into processing (secure defaults).",
        category="Security of processing",
        testing_procedures=["Secure-defaults / misconfig review"],
        expected_evidence=["Hardened default config"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="Art.33",
        title="Notification of a Personal Data Breach",
        description="Detect and (within 72h) notify breaches; requires detection capability.",
        category="Breach management",
        testing_procedures=["Incident/breach detection review"],
        expected_evidence=["SIEM / detection capability"],
        verdict_mode="auto",
    ),
    # --- Process / legal (manual — never auto-scored) ---
    ComplianceControl(
        id="Art.6",
        title="Lawfulness of Processing",
        description="Processing requires a valid lawful basis (consent, contract, legal obligation, …).",
        category="Lawful basis",
        testing_procedures=["Legal review"],
        expected_evidence=["Lawful-basis register"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="Art.7",
        title="Conditions for Consent",
        description="Where consent is the basis, it must be freely given, specific, informed, withdrawable.",
        category="Lawful basis",
        testing_procedures=["Consent-flow review"],
        expected_evidence=["Consent records"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="Art.15-22",
        title="Data Subject Rights",
        description="Access, rectification, erasure, portability, objection, and related rights.",
        category="Data subject rights",
        testing_procedures=["Rights-handling process review"],
        expected_evidence=["DSAR procedures"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="Art.30",
        title="Records of Processing Activities",
        description="Maintain records of processing activities.",
        category="Accountability",
        testing_procedures=["Documentation review"],
        expected_evidence=["RoPA document"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="Art.37",
        title="Data Protection Officer",
        description="Designate a DPO where required.",
        category="Accountability",
        testing_procedures=["Organisational review"],
        expected_evidence=["DPO appointment"],
        verdict_mode="manual",
    ),
]

# Only technical (Art. 32 / 25 / 33 / 5(1)(f)) controls are keyword-mapped.
_GDPR_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        ["weak tls", "weak ssl", "unencrypted", "plaintext", "cleartext", "encryption", "expired certificate"],
        ["Art.32(1)(a)"],
    ),
    (
        ["access control", "authorization", "idor", "privilege escalation", "privesc", "hardening", "open port"],
        ["Art.32(1)(b)"],
    ),
    (["backup", "recovery", "disaster", "availability", "denial of service", "dos"], ["Art.32(1)(c)"]),
    (["vulnerability", "cve-", "unpatched", "outdated", "end of life", "eol"], ["Art.32(1)(d)"]),
    (
        ["data exposure", "sensitive data", "information disclosure", "data leak", "pii", "personal data exposure"],
        ["Art.5(1)(f)"],
    ),
    (["misconfiguration", "default config", "insecure default", "default credential", "default password"], ["Art.25"]),
    (["incident", "breach", "compromise", "intrusion"], ["Art.33"]),
]


def map_finding_to_gdpr_controls(finding: Finding) -> list[str]:
    """Map a finding to GDPR article IDs (technical security measures only)."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _GDPR_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)
