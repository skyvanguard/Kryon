"""Findings table section — sortable table with severity badges and MITRE tags."""

from __future__ import annotations

from kryon.intelligence.models import Finding


def render_findings_table(findings: list[Finding], include_evidence: bool = True) -> str:
    """Render HTML table of findings with severity badges and MITRE tags."""
    # Sort by severity weight
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 5))

    rows = []
    for i, f in enumerate(sorted_findings, 1):
        mitre_tags = ""
        if f.mitre:
            tags = " ".join(f'<span class="mitre-tag">{m.technique_id}</span>' for m in f.mitre[:3])
            mitre_tags = tags

        cve_str = f.cve.cve_id if f.cve else "-"
        cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score else "-"

        evidence_cell = ""
        if include_evidence and f.evidence:
            evidence_cell = f'<td><pre class="evidence">{_escape(f.evidence[:500])}</pre></td>'

        rows.append(f"""
            <tr class="severity-{f.severity.value}">
                <td>{i}</td>
                <td><span class="sev-badge {f.severity.value}">{f.severity.value.upper()}</span></td>
                <td><strong>{_escape(f.title)}</strong><br><small>{_escape(f.description[:200])}</small></td>
                <td><code>{_escape(f.affected_asset)}</code></td>
                <td>{cve_str}</td>
                <td>{cvss_str}</td>
                <td>{mitre_tags}</td>
                <td>{_escape(f.tool_source)}</td>
                {evidence_cell}
                <td>{_escape(f.remediation[:200]) if f.remediation else "-"}</td>
            </tr>""")

    evidence_header = "<th>Evidence</th>" if include_evidence else ""

    return f"""
    <div class="findings-section">
        <h2>Detailed Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Asset</th>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>MITRE</th>
                    <th>Tool</th>
                    {evidence_header}
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>"""


def _escape(text: str) -> str:
    """Escape HTML special characters (incl. the single quote, for attribute contexts)."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
