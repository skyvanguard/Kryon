"""Compliance mapping section — PCI-DSS, MITIC (Paraguay), ISO 27001."""

from __future__ import annotations

from kryon.intelligence.models import Finding

# ---------------------------------------------------------------------------
# PCI-DSS v4.0 mapping
# ---------------------------------------------------------------------------
PCI_DSS_MAPPING: dict[str, dict] = {
    "open_ports": {
        "requirement": "1.1.6",
        "description": "Justification and documentation for all open ports/services",
    },
    "weak_ssl": {"requirement": "4.2.1", "description": "Strong cryptography for transmission of cardholder data"},
    "default_creds": {
        "requirement": "2.2.2",
        "description": "Change vendor-supplied defaults before installing on network",
    },
    "sql_injection": {"requirement": "6.2.4", "description": "Address common coding vulnerabilities — injection flaws"},
    "xss": {"requirement": "6.2.4", "description": "Address common coding vulnerabilities — XSS"},
    "access_control": {"requirement": "7.2.1", "description": "Appropriate access based on business need-to-know"},
    "patch_management": {"requirement": "6.3.3", "description": "Install critical security patches within one month"},
    "logging": {"requirement": "10.2.1", "description": "Audit trails for all access to cardholder data"},
    "network_segmentation": {"requirement": "1.3.1", "description": "Restrict inbound and outbound traffic"},
    "encryption_at_rest": {
        "requirement": "3.5.1",
        "description": "Protect stored account data with strong cryptography",
    },
    "weak_password": {"requirement": "8.3.6", "description": "Minimum password complexity requirements"},
    "mfa": {"requirement": "8.4.2", "description": "MFA for all access into the cardholder data environment"},
    "outdated_software": {"requirement": "6.3.1", "description": "Identify and manage security vulnerabilities"},
    "directory_listing": {"requirement": "6.2.4", "description": "Prevent information disclosure"},
    "file_upload": {"requirement": "6.2.4", "description": "Prevent unrestricted file upload"},
    "ssrf": {"requirement": "6.2.4", "description": "Prevent server-side request forgery"},
    "csrf": {"requirement": "6.2.4", "description": "Prevent cross-site request forgery"},
    "api_security": {"requirement": "6.2.4", "description": "Secure APIs against common attacks"},
    "data_exposure": {"requirement": "3.4.1", "description": "Render PAN unreadable anywhere it is stored"},
    "brute_force": {"requirement": "8.3.4", "description": "Account lockout after invalid authentication attempts"},
}

# ---------------------------------------------------------------------------
# MITIC (Paraguay) — Ley 6534/2020 + MITIC Resolution 234
# ---------------------------------------------------------------------------
MITIC_MAPPING: dict[str, dict] = {
    "data_exposure": {"articulo": "Art. 7", "description": "Proteccion de datos personales y sensibles"},
    "access_control": {"articulo": "Art. 12", "description": "Control de acceso a sistemas de informacion"},
    "logging": {"articulo": "Art. 15", "description": "Registro y monitoreo de actividades"},
    "encryption": {"articulo": "Art. 18", "description": "Cifrado de datos en transito y reposo"},
    "incident_response": {"articulo": "Art. 22", "description": "Plan de respuesta a incidentes de seguridad"},
    "patch_management": {"articulo": "Art. 14", "description": "Gestion de actualizaciones y parches de seguridad"},
    "network_security": {"articulo": "Art. 16", "description": "Seguridad perimetral y segmentacion de red"},
    "backup": {"articulo": "Art. 20", "description": "Respaldos y recuperacion ante desastres"},
    "awareness": {"articulo": "Art. 25", "description": "Capacitacion y concientizacion en seguridad"},
    "third_party": {"articulo": "Art. 28", "description": "Gestion de riesgos de terceros"},
}

# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A mapping
# ---------------------------------------------------------------------------
ISO_27001_MAPPING: dict[str, dict] = {
    "vulnerability_management": {"control": "A.8.8", "description": "Management of technical vulnerabilities"},
    "network_security": {"control": "A.8.20", "description": "Networks security"},
    "access_control": {"control": "A.8.3", "description": "Information access restriction"},
    "logging": {"control": "A.8.15", "description": "Logging"},
    "encryption": {"control": "A.8.24", "description": "Use of cryptography"},
    "patch_management": {"control": "A.8.8", "description": "Technical vulnerability management"},
    "data_exposure": {"control": "A.8.11", "description": "Data masking"},
    "backup": {"control": "A.8.13", "description": "Information backup"},
    "incident_response": {"control": "A.5.24", "description": "Information security incident management planning"},
    "change_management": {"control": "A.8.32", "description": "Change management"},
    "secure_development": {"control": "A.8.25", "description": "Secure development life cycle"},
    "supplier_security": {"control": "A.5.19", "description": "Information security in supplier relationships"},
    "malware": {"control": "A.8.7", "description": "Protection against malware"},
    "physical_security": {"control": "A.7.1", "description": "Physical security perimeters"},
    "identity_management": {"control": "A.5.16", "description": "Identity management"},
}

# Finding keyword → compliance category
_FINDING_TO_CATEGORY: list[tuple[list[str], str]] = [
    (["open port", "service discovery", "port scan"], "open_ports"),
    (["ssl", "tls", "certificate", "weak cipher"], "weak_ssl"),
    (["default password", "default credential", "admin/admin"], "default_creds"),
    (["sql injection", "sqli"], "sql_injection"),
    (["xss", "cross-site script"], "xss"),
    (["access control", "authorization", "idor"], "access_control"),
    (["outdated", "unpatched", "old version", "end of life"], "patch_management"),
    (["logging", "audit", "log file"], "logging"),
    (["segmentation", "flat network"], "network_segmentation"),
    (["encryption", "plaintext", "unencrypted"], "encryption"),
    (["weak password", "password policy"], "weak_password"),
    (["brute force", "credential stuffing"], "brute_force"),
    (["data exposure", "sensitive data", "information disclosure"], "data_exposure"),
    (["directory listing", "directory traversal"], "directory_listing"),
    (["file upload"], "file_upload"),
    (["ssrf", "server-side request"], "ssrf"),
    (["csrf", "cross-site request forgery"], "csrf"),
    (["api", "rest", "graphql"], "api_security"),
    (["malware", "trojan", "ransomware"], "malware"),
    (["vulnerability", "cve-"], "vulnerability_management"),
]


def _categorize_finding(finding: Finding) -> list[str]:
    """Map a finding to compliance categories via keywords."""
    text = f"{finding.title} {finding.description}".lower()
    categories = []
    for keywords, category in _FINDING_TO_CATEGORY:
        if any(kw in text for kw in keywords):
            categories.append(category)
    return categories or ["vulnerability_management"]


def render_compliance_mapping(findings: list[Finding], framework: str) -> str:
    """Render compliance mapping table for the specified framework."""
    framework = framework.lower().replace("-", "_").replace(" ", "_")

    if framework == "pci_dss" or framework == "pcidss":
        mapping = PCI_DSS_MAPPING
        title = "PCI-DSS v4.0"
        key_label = "Requirement"
    elif framework == "mitic":
        mapping = MITIC_MAPPING
        title = "MITIC (Paraguay)"
        key_label = "Articulo"
    elif framework == "iso27001" or framework == "iso_27001":
        mapping = ISO_27001_MAPPING
        title = "ISO 27001:2022"
        key_label = "Control"
    else:
        return f"<p>Unknown compliance framework: {framework}</p>"

    # Map findings to categories
    category_findings: dict[str, list[Finding]] = {}
    for f in findings:
        for cat in _categorize_finding(f):
            category_findings.setdefault(cat, []).append(f)

    # Build table rows for matched categories
    rows = []
    matched = set()
    for cat, cat_findings in sorted(category_findings.items()):
        if cat not in mapping:
            continue
        matched.add(cat)
        info = mapping[cat]
        ref = info.get("requirement") or info.get("articulo") or info.get("control", "")
        desc = info["description"]
        count = len(cat_findings)
        worst = _worst_severity(cat_findings)
        rows.append(f"""
            <tr>
                <td><code>{ref}</code></td>
                <td>{desc}</td>
                <td><span class="sev-badge {worst}">{worst.upper()}</span></td>
                <td>{count}</td>
            </tr>""")

    # Unmatched controls
    for cat, info in mapping.items():
        if cat not in matched:
            ref = info.get("requirement") or info.get("articulo") or info.get("control", "")
            rows.append(f"""
            <tr class="compliant">
                <td><code>{ref}</code></td>
                <td>{info["description"]}</td>
                <td><span class="sev-badge info">PASS</span></td>
                <td>0</td>
            </tr>""")

    return f"""
    <div class="compliance-section">
        <h2>Compliance Mapping — {title}</h2>
        <p>Controls with findings: <strong>{len(matched)}/{len(mapping)}</strong></p>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>{key_label}</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>"""


def _worst_severity(findings: list[Finding]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    sevs = {f.severity.value for f in findings}
    for s in order:
        if s in sevs:
            return s
    return "info"
