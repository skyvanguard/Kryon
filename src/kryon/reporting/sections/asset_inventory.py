"""Asset inventory section — discovered assets summary."""

from __future__ import annotations

from kryon.intelligence.models import Finding


def render_asset_inventory(findings: list[Finding]) -> str:
    """Render summary of all affected assets from findings."""
    assets: dict[str, dict] = {}
    for f in findings:
        asset = f.affected_asset
        if asset not in assets:
            assets[asset] = {"count": 0, "severities": set(), "tools": set()}
        assets[asset]["count"] += 1
        assets[asset]["severities"].add(f.severity.value)
        if f.tool_source:
            assets[asset]["tools"].add(f.tool_source)

    # Sort by finding count descending
    sorted_assets = sorted(assets.items(), key=lambda x: x[1]["count"], reverse=True)

    rows = []
    for asset, info in sorted_assets:
        worst = _worst_severity(info["severities"])
        tools = ", ".join(sorted(info["tools"])) or "-"
        rows.append(f"""
            <tr>
                <td><code>{asset}</code></td>
                <td>{info['count']}</td>
                <td><span class="sev-badge {worst}">{worst.upper()}</span></td>
                <td>{tools}</td>
            </tr>""")

    return f"""
    <div class="asset-inventory">
        <h2>Asset Inventory</h2>
        <p>Total unique assets: <strong>{len(assets)}</strong></p>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Asset</th>
                    <th>Findings</th>
                    <th>Worst Severity</th>
                    <th>Tools Used</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>"""


def _worst_severity(severities: set[str]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    for s in order:
        if s in severities:
            return s
    return "info"
