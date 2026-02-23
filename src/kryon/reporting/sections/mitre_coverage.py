"""MITRE ATT&CK coverage heatmap — inline SVG rendering."""

from __future__ import annotations

from kryon.intelligence.models import Finding, MITREMapping

# 14 Enterprise ATT&CK tactics in kill-chain order
_TACTICS = [
    ("TA0043", "Recon"),
    ("TA0042", "Resource Dev"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Priv Esc"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Cred Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Move"),
    ("TA0009", "Collection"),
    ("TA0011", "C2"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

_COLORS = {
    0: "#2d2d2d",  # not covered
    1: "#4a6741",  # 1 finding
    2: "#6b8f3c",  # 2-3 findings
    3: "#c9a227",  # 4-6 findings
    4: "#c44e52",  # 7+ findings
}


def render_mitre_heatmap(findings: list[Finding]) -> str:
    """Render inline SVG heatmap of ATT&CK tactic coverage."""
    # Collect all mappings
    all_mappings: list[MITREMapping] = []
    for f in findings:
        all_mappings.extend(f.mitre)

    # Count per tactic
    tactic_counts: dict[str, int] = {}
    for m in all_mappings:
        tactic_counts[m.tactic_id] = tactic_counts.get(m.tactic_id, 0) + 1

    # Count unique techniques per tactic
    tactic_techniques: dict[str, set[str]] = {}
    for m in all_mappings:
        tactic_techniques.setdefault(m.tactic_id, set()).add(m.technique_id)

    cell_w, cell_h = 100, 60
    margin = 10
    total_w = len(_TACTICS) * (cell_w + margin) + margin
    total_h = cell_h + 40 + margin * 2

    cells = []
    for i, (tid, tname) in enumerate(_TACTICS):
        x = margin + i * (cell_w + margin)
        y = margin
        count = tactic_counts.get(tid, 0)
        techniques = len(tactic_techniques.get(tid, set()))
        color_key = 0 if count == 0 else 1 if count == 1 else 2 if count <= 3 else 3 if count <= 6 else 4
        color = _COLORS[color_key]
        text_color = "#ffffff" if color_key > 0 else "#888888"

        cells.append(f"""
        <g>
            <rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" rx="4" fill="{color}" stroke="#444" stroke-width="1"/>
            <text x="{x + cell_w // 2}" y="{y + 20}" text-anchor="middle" fill="{text_color}" font-size="10" font-weight="bold">{tname}</text>
            <text x="{x + cell_w // 2}" y="{y + 35}" text-anchor="middle" fill="{text_color}" font-size="9">{tid}</text>
            <text x="{x + cell_w // 2}" y="{y + 50}" text-anchor="middle" fill="{text_color}" font-size="10">{techniques} tech</text>
        </g>""")

    covered = sum(1 for tid, _ in _TACTICS if tactic_counts.get(tid, 0) > 0)

    return f"""
    <div class="mitre-section">
        <h2>MITRE ATT&CK Coverage</h2>
        <p>Coverage: <strong>{covered}/14</strong> tactics ({covered * 100 // 14}%),
        <strong>{sum(len(s) for s in tactic_techniques.values())}</strong> unique techniques mapped.</p>
        <svg width="{total_w}" height="{total_h}" xmlns="http://www.w3.org/2000/svg"
             style="background: #1a1a1a; border-radius: 8px; padding: 5px;">
            {"".join(cells)}
        </svg>
        <div class="legend" style="margin-top:10px; font-size:12px; color:#999;">
            <span style="color:#2d2d2d">&#9632;</span> Not covered &nbsp;
            <span style="color:#4a6741">&#9632;</span> 1 &nbsp;
            <span style="color:#6b8f3c">&#9632;</span> 2-3 &nbsp;
            <span style="color:#c9a227">&#9632;</span> 4-6 &nbsp;
            <span style="color:#c44e52">&#9632;</span> 7+ findings
        </div>
    </div>"""
