"""Report section — attack path summary for HTML reports."""

from __future__ import annotations

import json


def render_attack_path_summary(findings: list) -> str:
    """Render attack path summary section for reports. Takes Finding models or dicts."""
    # Convert findings to dicts for correlator
    vuln_list = []
    for f in findings:
        if hasattr(f, "title"):
            vuln_list.append(
                {
                    "id": getattr(f, "id", ""),
                    "type": getattr(f, "title", "unknown"),
                    "severity": getattr(f, "severity", "medium").value
                    if hasattr(getattr(f, "severity", ""), "value")
                    else str(getattr(f, "severity", "medium")),
                    "location": getattr(f, "affected_asset", ""),
                }
            )
        elif isinstance(f, dict):
            vuln_list.append(f)

    if not vuln_list:
        return '<div class="section"><h2>Attack Path Analysis</h2><p>No findings to analyze.</p></div>'

    from kryon.tools.intelligence.vulnerability_correlator import correlate_vulnerabilities

    result = json.loads(correlate_vulnerabilities(json.dumps(vuln_list)))

    chains = result.get("attack_chains", [])
    if not chains:
        return '<div class="section"><h2>Attack Path Analysis</h2><p>No attack chains detected.</p></div>'

    rows = ""
    for chain in chains[:5]:  # Top 5
        stages = " &rarr; ".join(s.get("type", "?") for s in chain.get("stages", []))
        impact_cls = "critical" if chain.get("impact") == "critical" else "high"
        rows += f"""<tr>
<td class="severity-{impact_cls}">{chain.get("impact", "unknown")}</td>
<td>{chain.get("chain_type", "unknown")}</td>
<td>{stages}</td>
<td>{chain.get("description", "")}</td>
</tr>"""

    return f"""<div class="section">
<h2>Attack Path Analysis</h2>
<p>{len(chains)} attack chain(s) detected from {len(vuln_list)} findings.</p>
<table class="findings-table">
<thead><tr><th>Impact</th><th>Chain Type</th><th>Stages</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>"""
