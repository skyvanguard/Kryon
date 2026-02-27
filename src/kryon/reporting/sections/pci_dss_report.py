"""PCI-DSS compliance report section generator."""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework
from kryon.compliance.pci_dss import PCI_DSS_V4_CONTROLS
from kryon.intelligence.models import Finding

# Group controls by category (PCI-DSS 12 requirements)
_REQUIREMENT_CATEGORIES = {
    "Network Security": "1. Install and Maintain Network Security Controls",
    "System Configuration": "2. Apply Secure Configurations to All System Components",
    "Data Protection": "3. Protect Stored Account Data",
    "Encryption": "4. Protect Cardholder Data with Strong Cryptography",
    "Malware Protection": "5. Protect All Systems Against Malware",
    "Application Security": "6. Develop and Maintain Secure Systems and Software",
    "Access Control": "7. Restrict Access to System Components",
    "Authentication": "8. Identify Users and Authenticate Access",
    "Logging & Monitoring": "10. Log and Monitor All Access to System Components",
    "Testing": "11. Test Security of Systems and Networks Regularly",
    "Policy": "12. Support Information Security with Organizational Policies",
    "Vulnerability Management": "6. Develop and Maintain Secure Systems and Software",
}


def render_pci_dss_report(findings: list[Finding]) -> str:
    """Generate a full PCI-DSS v4.0 compliance report section."""
    report = map_findings_to_framework(findings, "pci_dss")

    # Build evidence lookup
    evidence_by_id = {e.control_id: e for e in report.evidence}

    # Build control lookup
    controls_by_id = {c.id: c for c in PCI_DSS_V4_CONTROLS}

    # Group by category
    categories: dict[str, list[str]] = {}
    for ctrl in PCI_DSS_V4_CONTROLS:
        categories.setdefault(ctrl.category, []).append(ctrl.id)

    # Executive summary
    status_class = "pass" if report.controls_failed == 0 else "fail"
    summary = f"""
    <div class="compliance-executive-summary">
        <h2>PCI-DSS v4.0 Compliance Assessment</h2>
        <div class="compliance-stats">
            <div class="stat">
                <span class="stat-value">{report.controls_assessed}</span>
                <span class="stat-label">Controls Assessed</span>
            </div>
            <div class="stat pass">
                <span class="stat-value">{report.controls_passed}</span>
                <span class="stat-label">Passed</span>
            </div>
            <div class="stat {status_class}">
                <span class="stat-value">{report.controls_failed}</span>
                <span class="stat-label">Failed</span>
            </div>
            <div class="stat">
                <span class="stat-value">{report.compliance_percentage}%</span>
                <span class="stat-label">Compliance</span>
            </div>
        </div>
    </div>"""

    # Requirement sections
    sections = []
    for category, cat_title in _REQUIREMENT_CATEGORIES.items():
        ctrl_ids = categories.get(category, [])
        if not ctrl_ids:
            continue

        rows = []
        for ctrl_id in ctrl_ids:
            ctrl = controls_by_id.get(ctrl_id)
            ev = evidence_by_id.get(ctrl_id)
            if not ctrl or not ev:
                continue
            status_badge = "pass" if ev.status == "pass" else "fail"
            finding_count = len(ev.findings)
            rows.append(f"""
                <tr>
                    <td><code>{ctrl.id}</code></td>
                    <td>{ctrl.title}</td>
                    <td><span class="sev-badge {status_badge}">{ev.status.upper()}</span></td>
                    <td>{finding_count}</td>
                </tr>""")

        sections.append(f"""
        <div class="pci-requirement">
            <h3>{cat_title}</h3>
            <table class="findings-table">
                <thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Findings</th></tr></thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        </div>""")

    return summary + "\n".join(sections)
