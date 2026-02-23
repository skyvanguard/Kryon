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

    # Gauge color
    if score >= 80:
        gauge_color = "#c44e52"
        risk_label = "CRITICAL"
    elif score >= 60:
        gauge_color = "#d4833c"
        risk_label = "HIGH"
    elif score >= 40:
        gauge_color = "#c9a227"
        risk_label = "MEDIUM"
    elif score >= 20:
        gauge_color = "#6b8f3c"
        risk_label = "LOW"
    else:
        gauge_color = "#4a6741"
        risk_label = "MINIMAL"

    # SVG gauge (semi-circle)
    angle = score / 100 * 180
    rad = 3.14159 * angle / 180
    import math

    end_x = 150 + 100 * math.cos(3.14159 - rad)
    end_y = 120 - 100 * math.sin(3.14159 - rad)
    large_arc = 1 if angle > 90 else 0

    # Severity distribution bars
    max_count = max(counts.values()) if counts else 1
    bars = []
    sev_colors = {"critical": "#c44e52", "high": "#d4833c", "medium": "#c9a227", "low": "#6b8f3c", "info": "#5599cc"}
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = counts.get(sev, 0)
        bar_w = (c / max_count * 200) if max_count > 0 else 0
        bars.append(f"""
            <div style="display:flex;align-items:center;margin:4px 0;">
                <span style="width:80px;text-transform:uppercase;font-size:12px;color:{sev_colors[sev]}">{sev}</span>
                <div style="background:{sev_colors[sev]};width:{bar_w}px;height:20px;border-radius:3px;margin-right:8px;"></div>
                <span style="color:#ccc;font-size:14px;font-weight:bold;">{c}</span>
            </div>""")

    return f"""
    <div class="risk-overview">
        <h2>Risk Overview</h2>
        <div style="display:flex;gap:40px;flex-wrap:wrap;">
            <div>
                <svg width="300" height="160" xmlns="http://www.w3.org/2000/svg">
                    <path d="M 50 120 A 100 100 0 0 1 250 120" fill="none" stroke="#333" stroke-width="20" stroke-linecap="round"/>
                    <path d="M 50 120 A 100 100 0 {large_arc} 1 {end_x:.1f} {end_y:.1f}" fill="none" stroke="{gauge_color}" stroke-width="20" stroke-linecap="round"/>
                    <text x="150" y="110" text-anchor="middle" fill="{gauge_color}" font-size="36" font-weight="bold">{score}</text>
                    <text x="150" y="135" text-anchor="middle" fill="#999" font-size="14">{risk_label}</text>
                </svg>
            </div>
            <div>
                <h3 style="color:#eee;">Severity Distribution</h3>
                {"".join(bars)}
            </div>
        </div>
        <p style="color:#888;font-size:12px;margin-top:10px;">
            Total findings: {len(findings)} | Risk score: {score}/100
        </p>
    </div>"""


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts
