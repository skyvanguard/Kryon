"""PSD2 RTS (Commission Delegated Regulation (EU) 2018/389) — SCA & secure
communication control catalog + finding mapping, with a FAPI 1.0 Advanced
bridge.

HONEST SCOPE: a scanner validates only the *technical* RTS controls that a
FAPI discovery-document audit (or the normal finding stream) can evidence —
SCA announcement, dynamic linking, credential integrity, secure communication.
Process/legal controls (transaction-risk monitoring, SCA exemptions, incident
reporting, PISP/AISP licensing & liability) carry ``verdict_mode="manual"``
and are NEVER auto-scored. Do not claim "PSD2 compliant" from this — claim
"RTS technical controls mapped".

The FAPI bridge (`fapi_report_to_findings`) turns a `FAPIComplianceReport`
from `tools.api.fapi_validator` into Finding objects, so the existing FAPI
1.0 Advanced validator feeds this framework's finding→control mapping.

Version check (2026-07): PSD2 RTS = Commission Delegated Regulation (EU)
2018/389, in force since Sep 2019 and STILL the applicable regime. PSD3 + PSR
(texts agreed Apr 2026) will apply ~21 months after Official-Journal
publication (~2028) and retain/refine SCA — not yet in force. FAPI 1.0
Advanced remains the profile required by most Open Banking regimes (UK OBIE,
Brazil OBB, BCP Paraguay); FAPI 2.0 Security Profile (Final Feb 2025) is the
newer, simpler alternative — roadmap, not yet required here.
"""

from __future__ import annotations

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding, Severity

FRAMEWORK_NAME = "PSD2 RTS (SCA & Secure Communication)"

PSD2_CONTROLS: list[ComplianceControl] = [
    # --- Technical RTS (auto — scanner / FAPI-verifiable) ---
    ComplianceControl(
        id="RTS-Art4",
        title="Strong Customer Authentication",
        description="Two independent elements from knowledge / possession / inherence to authenticate the PSU.",
        category="Authentication (RTS Ch.2)",
        testing_procedures=["SCA / MFA enforcement testing", "FAPI ACR/AMR announcement"],
        expected_evidence=["MFA config", "acr_values_supported / amr_values_supported"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="RTS-Art5",
        title="Dynamic linking",
        description="Authorisation code dynamically linked to the specific transaction amount and payee.",
        category="Authentication (RTS Ch.2)",
        testing_procedures=["PAR / request-object binding", "authorization request integrity"],
        expected_evidence=["PAR endpoint", "signed request objects"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="RTS-Art9",
        title="Independence of authentication elements",
        description="Breach of one authentication element must not compromise the others (sender-constrained tokens).",
        category="Authentication (RTS Ch.2)",
        testing_procedures=["mTLS-bound / DPoP token verification"],
        expected_evidence=["tls_client_certificate_bound_access_tokens", "DPoP algs"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="RTS-Art22",
        title="Confidentiality and integrity of credentials",
        description="Security credentials & authentication data protected with strong asymmetric cryptography.",
        category="Credentials (RTS Ch.3)",
        testing_procedures=["Signing-algorithm review (PS256/ES256)", "JARM signed responses"],
        expected_evidence=["id_token / request-object signing algs"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="RTS-Art30",
        title="Common and secure open standards of communication",
        description="Dedicated interface using secure open standards — FAPI 1.0 Advanced (PAR, PKCE S256, "
        "no implicit flow, strong client auth).",
        category="Secure Communication (RTS Ch.5)",
        testing_procedures=["FAPI 1.0 Advanced discovery-doc audit"],
        expected_evidence=["FAPI conformance report"],
        verdict_mode="auto",
    ),
    ComplianceControl(
        id="RTS-Art35",
        title="Secure communication session (strong encryption in transit)",
        description="Strong, widely recognised encryption for every session carrying personalised security data.",
        category="Secure Communication (RTS Ch.5)",
        testing_procedures=["TLS >= 1.2 / cipher review"],
        expected_evidence=["TLS config"],
        verdict_mode="auto",
    ),
    # --- Process / legal (manual — never auto-scored) ---
    ComplianceControl(
        id="RTS-Art2",
        title="Transaction risk monitoring",
        description="Real-time transaction-risk analysis to detect unauthorised or fraudulent payments.",
        category="General (RTS Ch.1)",
        testing_procedures=["Fraud-engine review / interview"],
        expected_evidence=["TRA policy", "fraud-rate reporting"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="RTS-Art10-18",
        title="SCA exemptions",
        description="Application and monitoring of RTS exemptions (low-value, TRA, trusted beneficiaries, …).",
        category="Exemptions (RTS Ch.3)",
        testing_procedures=["Exemption-policy review"],
        expected_evidence=["Exemption logic + audit trail"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="DIR-Art96",
        title="Major incident reporting",
        description="Report major operational or security incidents to the competent authority.",
        category="Directive (EU) 2015/2366",
        testing_procedures=["Incident-reporting procedure review"],
        expected_evidence=["Incident register", "regulator notifications"],
        verdict_mode="manual",
    ),
    ComplianceControl(
        id="DIR-License",
        title="PISP/AISP authorisation & liability",
        description="Provider licensing, professional-indemnity cover, and liability apportionment under the Directive.",
        category="Directive (EU) 2015/2366",
        testing_procedures=["Licence + contract review"],
        expected_evidence=["Regulator authorisation", "PI insurance cover"],
        verdict_mode="manual",
    ),
]

# Only technical RTS controls are keyword-mapped. The manual controls above are
# intentionally absent — a scanner cannot verify them.
_PSD2_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        [
            "sca",
            "strong customer authentication",
            "mfa",
            "multi-factor",
            "two-factor",
            "2fa",
            "authentication bypass",
            "weak authentication",
            "acr",
            "amr",
        ],
        ["RTS-Art4"],
    ),
    (
        [
            "dynamic linking",
            "pushed authorization",
            "par endpoint",
            "request object",
            "transaction binding",
            "request binding",
        ],
        ["RTS-Art5"],
    ),
    (
        ["sender-constrained", "token binding", "mtls-bound", "dpop", "token replay", "independence of authentication"],
        ["RTS-Art9"],
    ),
    (
        [
            "credential",
            "signing algorithm",
            "ps256",
            "es256",
            "rs256",
            "weak signature",
            "jarm",
            "id token signing",
            "integrity of credentials",
        ],
        ["RTS-Art22"],
    ),
    (
        [
            "fapi",
            "pkce",
            "implicit flow",
            "hybrid flow",
            "code_challenge",
            "secure open standard",
            "eidas",
            "dedicated interface",
            "open banking api",
        ],
        ["RTS-Art30"],
    ),
    (
        [
            "weak tls",
            "weak ssl",
            "cleartext",
            "plaintext",
            "insecure transmission",
            "cipher",
            "expired certificate",
            "tls 1.0",
            "tls 1.1",
            "sslv3",
            "secure communication",
        ],
        ["RTS-Art35"],
    ),
]


def map_finding_to_psd2_controls(finding: Finding) -> list[str]:
    """Map a finding to PSD2 RTS technical control IDs (auto controls only)."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _PSD2_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(control_ids)
    return sorted(matched)


# ---------------------------------------------------------------------------
# FAPI 1.0 Advanced bridge
# ---------------------------------------------------------------------------

# Each FAPI check maps to the RTS control it evidences. The anchor phrase is
# injected into the generated finding's text so the keyword mapper resolves it
# deterministically (in addition to RTS-Art30, which every FAPI gap implies).
_FAPI_CHECK_TO_RTS: dict[str, tuple[str, str]] = {
    "FAPI-1": ("RTS-Art5", "dynamic linking / pushed authorization request"),
    "FAPI-2": ("RTS-Art22", "integrity of credentials / request-object signing algorithm"),
    "FAPI-3": ("RTS-Art22", "integrity of credentials / id token signing algorithm"),
    "FAPI-4": ("RTS-Art30", "secure open standard / strong client authentication"),
    "FAPI-5": ("RTS-Art9", "independence of authentication / sender-constrained token"),
    "FAPI-6": ("RTS-Art30", "secure open standard / PKCE"),
    "FAPI-7": ("RTS-Art30", "secure open standard / implicit flow disabled"),
    "FAPI-8": ("RTS-Art22", "integrity of credentials / JARM signed response"),
    "FAPI-9": ("RTS-Art30", "secure open standard / open banking api scopes"),
    "FAPI-10": ("RTS-Art4", "strong customer authentication / acr amr announcement"),
}

_FAPI_SEVERITY_TO_KRYON = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.INFO,
}


def fapi_report_to_findings(report) -> list[Finding]:
    """Convert the failing / warning checks of a FAPIComplianceReport into
    Finding objects, so the FAPI 1.0 Advanced validator feeds the PSD2
    framework's finding->control mapping.

    Only non-pass, non-inapplicable checks become findings — a passing control
    is not a finding. The generated text carries a `fapi` anchor plus the
    per-check RTS anchor so `map_finding_to_psd2_controls` resolves the right
    controls.
    """
    findings: list[Finding] = []
    for r in report.results:
        if r.status in ("pass", "inapplicable"):
            continue
        _rts_id, anchor = _FAPI_CHECK_TO_RTS.get(r.check_id, ("RTS-Art30", "secure open standard / fapi"))
        findings.append(
            Finding(
                title=f"FAPI {r.check_id}: {r.title}",
                description=f"{r.rationale} Expected {r.expected}; got {r.actual}. PSD2 RTS anchor: {anchor}.",
                severity=_FAPI_SEVERITY_TO_KRYON.get(r.severity, Severity.MEDIUM),
                affected_asset=report.issuer or "authorization-server",
                remediation=r.remediation,
                tool_source="fapi_validator",
            )
        )
    return findings
