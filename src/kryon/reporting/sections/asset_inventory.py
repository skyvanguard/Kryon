"""Asset inventory section — discovered assets summary."""

from __future__ import annotations

from kryon.intelligence.models import Finding


def render_asset_inventory(findings: list[Finding]) -> str:
    """Render a summary of affected assets, grouped by host (port-agnostic).

    `example.com:443` and `example.com` are the same asset (web vs DNS/email findings);
    grouping by the bare host avoids listing one host as several "assets".
    """
    sev_es = {"critical": "Crítico", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Info"}
    assets: dict[str, dict] = {}
    for f in findings:
        host = _host_of(f.affected_asset)
        info = assets.setdefault(host, {"count": 0, "severities": set(), "tools": set(), "ports": set()})
        info["count"] += 1
        info["severities"].add(f.severity.value)
        if f.tool_source:
            info["tools"].add(f.tool_source)
        port = _port_of(f.affected_asset)
        if port:
            info["ports"].add(port)

    sorted_assets = sorted(assets.items(), key=lambda x: x[1]["count"], reverse=True)

    rows = []
    for host, info in sorted_assets:
        worst = _worst_severity(info["severities"])
        tools = ", ".join(sorted(info["tools"])) or "-"
        ports = ", ".join(sorted(info["ports"], key=lambda p: int(p) if p.isdigit() else 0)) or "—"
        rows.append(f"""
            <tr>
                <td><code>{host}</code></td>
                <td>{ports}</td>
                <td>{info["count"]}</td>
                <td><span class="sev-badge {worst}">{sev_es.get(worst, worst).upper()}</span></td>
                <td>{tools}</td>
            </tr>""")

    return f"""
    <div class="asset-inventory">
        <h2>Inventario de activos</h2>
        <p>Activos únicos: <strong>{len(assets)}</strong></p>
        <table class="findings-table asset-table">
            <thead>
                <tr>
                    <th>Activo</th>
                    <th>Puertos</th>
                    <th>Hallazgos</th>
                    <th>Severidad máx.</th>
                    <th>Herramientas</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>"""


def _host_of(asset: str) -> str:
    """Strip a trailing :port (digits only) so host:443 and host collapse to one asset."""
    if ":" in asset:
        head, _, tail = asset.rpartition(":")
        if head and tail.isdigit():
            return head
    return asset


def _port_of(asset: str) -> str:
    if ":" in asset:
        _, _, tail = asset.rpartition(":")
        if tail.isdigit():
            return tail
    return ""


def _worst_severity(severities: set[str]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    for s in order:
        if s in severities:
            return s
    return "info"
