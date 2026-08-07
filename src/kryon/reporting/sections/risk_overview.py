"""Risk overview section — score gauge + severity distribution."""

from __future__ import annotations

from kryon.intelligence.models import Finding, Severity

# Weights for risk score calculation
_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}


def calculate_risk_score(findings: list[Finding]) -> float:
    """Calculate aggregate risk score (0-100) from findings."""
    if not findings:
        return 0.0

    total_weight = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    # Normalize: 100 = 10 critical findings equivalent
    max_ref = 10 * _SEVERITY_WEIGHTS[Severity.CRITICAL]
    score = min(total_weight / max_ref * 100, 100.0)

    # Boost for EPSS high scores and CISA KEV
    for f in findings:
        if f.cve:
            if f.cve.epss_score and f.cve.epss_score > 0.5:
                score = min(score + 2.0, 100.0)
            if f.cve.cisa_kev:
                score = min(score + 3.0, 100.0)
            if f.cve.exploit_available:
                score = min(score + 1.5, 100.0)

    return round(score, 1)


def render_risk_overview(findings: list[Finding]) -> str:
    """Render risk score gauge and severity distribution."""
    score = calculate_risk_score(findings)
    counts = _count_by_severity(findings)

    # Gauge color — darker, high-contrast palette for the light theme.
    if score >= 80:
        gauge_color, risk_label = "#b3261e", "CRÍTICO"
    elif score >= 60:
        gauge_color, risk_label = "#b5531a", "ALTO"
    elif score >= 40:
        gauge_color, risk_label = "#8a6d08", "MEDIO"
    elif score >= 20:
        gauge_color, risk_label = "#3f6f2a", "BAJO"
    else:
        gauge_color, risk_label = "#3f6f2a", "MÍNIMO"

    # SVG gauge (semi-circle)
    angle = score / 100 * 180
    rad = 3.14159 * angle / 180
    import math

    end_x = 150 + 100 * math.cos(3.14159 - rad)
    end_y = 120 - 100 * math.sin(3.14159 - rad)
    large_arc = 1 if angle > 90 else 0

    # Severity distribution bars — dark labels/counts (readable on white), colored bars.
    max_count = max(counts.values()) if counts else 1
    bars = []
    sev_colors = {"critical": "#b3261e", "high": "#b5531a", "medium": "#8a6d08", "low": "#3f6f2a", "info": "#0a52c4"}
    sev_es = {"critical": "Crítico", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Info"}
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = counts.get(sev, 0)
        pct = (c / max_count * 100) if max_count > 0 else 0
        bars.append(f"""
            <div style="display:flex;align-items:center;margin:6px 0;">
                <span style="width:70px;font-size:12px;color:#14181f;font-weight:600;">{sev_es[sev]}</span>
                <div style="flex:1;max-width:240px;background:#eef1f4;border-radius:3px;height:20px;overflow:hidden;">
                    <div style="background:{sev_colors[sev]};width:{pct:.0f}%;height:20px;"></div>
                </div>
                <span style="color:#14181f;font-size:14px;font-weight:bold;margin-left:10px;width:24px;">{c}</span>
            </div>""")

    return f"""
    <div class="risk-overview">
        <h2>Panorama de riesgo</h2>
        <div style="display:flex;gap:40px;flex-wrap:wrap;align-items:center;">
            <div>
                <svg width="300" height="160" xmlns="http://www.w3.org/2000/svg">
                    <path d="M 50 120 A 100 100 0 0 1 250 120" fill="none" stroke="#e3e7ec" stroke-width="20" stroke-linecap="round"/>
                    <path d="M 50 120 A 100 100 0 {large_arc} 1 {end_x:.1f} {end_y:.1f}" fill="none" stroke="{gauge_color}" stroke-width="20" stroke-linecap="round"/>
                    <text x="150" y="110" text-anchor="middle" fill="{gauge_color}" font-size="36" font-weight="bold">{score}</text>
                    <text x="150" y="135" text-anchor="middle" fill="#4b545f" font-size="14" font-weight="bold">{risk_label}</text>
                </svg>
            </div>
            <div style="min-width:340px;">
                <h3 style="color:#14181f;margin-bottom:8px;">Distribución por severidad</h3>
                {"".join(bars)}
            </div>
        </div>
        <p style="color:#4b545f;font-size:12px;margin-top:12px;">
            Total de hallazgos: <strong>{len(findings)}</strong> &nbsp;·&nbsp; Score de riesgo: <strong>{score}/100</strong>
        </p>
    </div>"""


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts
