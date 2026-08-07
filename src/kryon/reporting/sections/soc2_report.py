"""SOC 2 Type II compliance report section generator."""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework
from kryon.compliance.soc2 import SOC2_TSC_CONTROLS
from kryon.intelligence.models import Finding

_TSC_CATEGORIES = {
    "Security": "Security (Common Criteria)",
    "Availability": "Availability",
    "Processing Integrity": "Processing Integrity",
    "Confidentiality": "Confidentiality",
    "Privacy": "Privacy",
}


def render_soc2_report(findings: list[Finding]) -> str:
    """Generate a full SOC 2 Type II compliance report section."""
    report = map_findings_to_framework(findings, "soc2")

    evidence_by_id = {e.control_id: e for e in report.evidence}
    controls_by_id = {c.id: c for c in SOC2_TSC_CONTROLS}

    categories: dict[str, list[str]] = {}
    for ctrl in SOC2_TSC_CONTROLS:
        categories.setdefault(ctrl.category, []).append(ctrl.id)

    status_class = "pass" if report.controls_failed == 0 else "fail"
    summary = f"""
    <div class="compliance-executive-summary">
        <h2>SOC 2 Type II Compliance Assessment</h2>
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

    sections = []
    for category, tsc_title in _TSC_CATEGORIES.items():
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
                    <td>{ctrl.description}</td>
                    <td><span class="sev-badge {status_badge}">{ev.status.upper()}</span></td>
                    <td>{finding_count}</td>
                </tr>""")

        sections.append(f"""
        <div class="soc2-tsc">
            <h3>{tsc_title}</h3>
            <table class="findings-table">
                <thead><tr><th>Control</th><th>Title</th><th>Description</th><th>Status</th><th>Findings</th></tr></thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        </div>""")

    return summary + "\n".join(sections)
