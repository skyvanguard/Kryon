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

# Coverage level → (cell background, text color). Light theme, high contrast.
_COLORS = {
    0: ("#eef1f4", "#9aa3ad"),  # not covered (light gray)
    1: ("#3f6f2a", "#ffffff"),  # 1 finding
    2: ("#5e8a36", "#ffffff"),  # 2-3 findings
    3: ("#8a6d08", "#ffffff"),  # 4-6 findings
    4: ("#b3261e", "#ffffff"),  # 7+ findings
}


def render_mitre_heatmap(findings: list[Finding]) -> str:
    """Render a responsive HTML grid of ATT&CK tactic coverage (wraps to fit the PDF page).

    The previous fixed-width inline SVG (14 cells × 110px ≈ 1540px) overflowed an A4 page and clipped.
    A CSS grid auto-wraps to 2-3 rows and inherits the light report theme.
    """
    all_mappings: list[MITREMapping] = []
    for f in findings:
        all_mappings.extend(f.mitre)

    tactic_counts: dict[str, int] = {}
    tactic_techniques: dict[str, set[str]] = {}
    for m in all_mappings:
        tactic_counts[m.tactic_id] = tactic_counts.get(m.tactic_id, 0) + 1
        tactic_techniques.setdefault(m.tactic_id, set()).add(m.technique_id)

    cells = []
    for tid, tname in _TACTICS:
        count = tactic_counts.get(tid, 0)
        techniques = len(tactic_techniques.get(tid, set()))
        color_key = 0 if count == 0 else 1 if count == 1 else 2 if count <= 3 else 3 if count <= 6 else 4
        bg, fg = _COLORS[color_key]
        cells.append(f"""
            <div class="mitre-cell" style="background:{bg};color:{fg};">
                <div class="mitre-name">{tname}</div>
                <div class="mitre-id">{tid}</div>
                <div class="mitre-tech">{techniques} téc.</div>
            </div>""")

    covered = sum(1 for tid, _ in _TACTICS if tactic_counts.get(tid, 0) > 0)
    legend = (
        '<span class="lg" style="background:#eef1f4;border:1px solid #d0d7de;"></span> Sin cobertura &nbsp;'
        '<span class="lg" style="background:#3f6f2a;"></span> 1 &nbsp;'
        '<span class="lg" style="background:#5e8a36;"></span> 2-3 &nbsp;'
        '<span class="lg" style="background:#8a6d08;"></span> 4-6 &nbsp;'
        '<span class="lg" style="background:#b3261e;"></span> 7+ hallazgos'
    )

    return f"""
    <div class="mitre-section">
        <h2>Cobertura MITRE ATT&amp;CK</h2>
        <p>Cobertura: <strong>{covered}/14</strong> tácticas ({covered * 100 // 14}%),
        <strong>{sum(len(s) for s in tactic_techniques.values())}</strong> técnicas únicas mapeadas.</p>
        <div class="mitre-grid">{"".join(cells)}</div>
        <div class="mitre-legend">{legend}</div>
    </div>"""
