"""Executive summary section — non-technical C-level overview."""

from __future__ import annotations

from kryon.intelligence.models import Finding, Severity


def render_executive_summary(
    findings: list[Finding], client_name: str = "", scope: str = ""
) -> str:
    """Generate an executive summary from findings (no LLM, template-based)."""
    total = len(findings)
    by_sev = _count_by_severity(findings)
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    risk_level = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MODERATE" if by_sev.get("medium", 0) > 0 else "LOW"

    client_str = f" for <strong>{client_name}</strong>" if client_name else ""
    scope_str = f" targeting <code>{scope}</code>" if scope else ""

    summary = f"""
    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <p>The security assessment{client_str}{scope_str} identified
        <strong>{total} findings</strong> across the evaluated attack surface.
        The overall risk level is assessed as <span class="risk-{risk_level.lower()}">{risk_level}</span>.</p>

        <div class="severity-summary">
            <div class="sev-badge critical">{critical} Critical</div>
            <div class="sev-badge high">{high} High</div>
            <div class="sev-badge medium">{by_sev.get('medium', 0)} Medium</div>
            <div class="sev-badge low">{by_sev.get('low', 0)} Low</div>
            <div class="sev-badge info">{by_sev.get('info', 0)} Info</div>
        </div>
    """

    if critical > 0:
        crit_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        summary += "\n        <h3>Critical Issues Requiring Immediate Attention</h3>\n        <ul>\n"
        for f in crit_findings[:5]:
            summary += f"            <li><strong>{f.title}</strong> — {f.affected_asset}</li>\n"
        summary += "        </ul>\n"

    summary += "    </div>"
    return summary


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts
