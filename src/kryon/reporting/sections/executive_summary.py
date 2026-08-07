"""Executive summary section — non-technical C-level overview.

F85.G — Now prepends an LLM-narrated 3-paragraph business-impact
analysis on top of the deterministic counts. The narrative is best-
effort: any failure (LLM unreachable, malformed output, missing
KRYON_EXEC_NARRATIVE=true opt-in) falls back to the template-only
view silently so the PDF still ships.

The LLM section is opt-in via ``KRYON_EXEC_NARRATIVE=true`` env
because it adds ~$0.005 per report and the report path runs in
demo/CI contexts where deterministic output is preferred.
"""

from __future__ import annotations

import os

from kryon.intelligence.models import Finding, Severity
from kryon.reporting.exec_narrative import (
    generate_executive_narrative,
    render_narrative_as_html,
)


def render_executive_summary(findings: list[Finding], client_name: str = "", scope: str = "") -> str:
    """Generate an executive summary from findings.

    Layout:
      [LLM narrative — only if KRYON_EXEC_NARRATIVE=true and the call
       succeeded]
      Deterministic counts + critical issues list (always)
    """
    total = len(findings)
    by_sev = _count_by_severity(findings)
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    risk_key = (
        "critical" if critical > 0 else "high" if high > 0 else "moderate" if by_sev.get("medium", 0) > 0 else "low"
    )
    risk_es = {"critical": "CRÍTICO", "high": "ALTO", "moderate": "MODERADO", "low": "BAJO"}[risk_key]

    # Escape target/LLM-derived values — they reach HTML→PDF and could inject markup
    # or break layout (findings_table already escapes its cells; these were raw).
    from kryon.reporting.sections.findings_table import _escape  # noqa: PLC0415

    client_str = f" para <strong>{_escape(client_name)}</strong>" if client_name else ""
    scope_str = f" sobre <code>{_escape(scope)}</code>" if scope else ""

    # Opt-in LLM narrative. Demos / CI keep the deterministic-only
    # path because reports are diffed against snapshots.
    narrative_html = ""
    if os.environ.get("KRYON_EXEC_NARRATIVE", "").strip().lower() in {"1", "true", "yes"}:
        try:
            narrative = generate_executive_narrative(
                findings,
                client_name=client_name,
                scope=scope,
            )
            narrative_html = render_narrative_as_html(narrative)
        except Exception:
            narrative_html = ""

    sev_word = {"critical": "Crítico", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Info"}
    plural = "hallazgos" if total != 1 else "hallazgo"

    summary = f"""
    <div class="executive-summary">
        <h2>Resumen ejecutivo</h2>
        {narrative_html}
        <p>La evaluación de seguridad{client_str}{scope_str} identificó
        <strong>{total} {plural}</strong> en la superficie de ataque evaluada.
        El nivel de riesgo global se valora como <span class="risk-{risk_key}">{risk_es}</span>.</p>

        <div class="severity-summary">
            <div class="sev-badge critical">{critical} Crítico</div>
            <div class="sev-badge high">{high} Alto</div>
            <div class="sev-badge medium">{by_sev.get("medium", 0)} Medio</div>
            <div class="sev-badge low">{by_sev.get("low", 0)} Bajo</div>
            <div class="sev-badge info">{by_sev.get("info", 0)} Info</div>
        </div>
    """

    # Thematic grouping — gives the reader the "what kind of issues" at a glance.
    themes = _group_by_theme(findings)
    if len(themes) > 1 or (themes and total > 1):
        items = " &nbsp;·&nbsp; ".join(f"{name} ({n})" for name, n in themes)
        summary += f'\n        <p><strong>Distribución temática:</strong> {items}.</p>\n'

    # Risk-aware takeaway.
    takeaway = _takeaway(risk_key, critical, high)
    summary += f'\n        <p><strong>Conclusión:</strong> {takeaway}</p>\n'

    if critical > 0 or high > 0:
        urgent = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        summary += "\n        <h3>Hallazgos prioritarios</h3>\n        <ul>\n"
        for f in urgent[:5]:
            sw = sev_word.get(f.severity.value, f.severity.value)
            summary += f"            <li><strong>{_escape(f.title)}</strong> ({sw}) — {_escape(f.affected_asset)}</li>\n"
        summary += "        </ul>\n"

    summary += "    </div>"
    return summary


# Theme buckets keyed by substrings found in the rule_id / title / CWE text. Generalisable
# beyond the current web/DNS findings; anything unmatched falls into "Otros".
_THEME_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Higiene DNS y correo", ("dmarc", "spf", "dkim", "caa", "mta-sts", "tls-rpt", "mx", "dnssec")),
    ("Cabeceras y políticas web", ("csp", "hsts", "csrf", "referrer", "x-frame", "cookie", "header", "cors", "clickjack")),
    ("Configuración TLS/SSL", ("tls", "ssl", "cipher", "cert", "certificate")),
    ("Exposición de servicios", ("smb", "redis", "rdp", "ssh", "ftp", "snmp", "port", "banner")),
    ("Vulnerabilidades de aplicación", ("sqli", "xss", "rce", "ssrf", "lfi", "idor", "injection", "traversal", "deser")),
]


def _group_by_theme(findings: list[Finding]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in findings:
        hay = f"{getattr(f, 'rule_id', '') or ''} {f.title}".lower()
        label = "Otros"
        for name, keys in _THEME_RULES:
            if any(k in hay for k in keys):
                label = name
                break
        counts[label] = counts.get(label, 0) + 1
    # Most-common theme first; "Otros" always last.
    return sorted(counts.items(), key=lambda kv: (kv[0] == "Otros", -kv[1]))


def _takeaway(risk_key: str, critical: int, high: int) -> str:
    if risk_key == "critical":
        return (
            f"Se identificaron <strong>{critical} hallazgo(s) crítico(s)</strong> que requieren remediación "
            "inmediata; representan riesgo directo de compromiso. Priorizar su corrección antes de cualquier otra tarea."
        )
    if risk_key == "high":
        return (
            f"Se identificaron <strong>{high} hallazgo(s) de severidad alta</strong> que deberían remediarse a corto "
            "plazo. No se observaron problemas críticos, pero la exposición es relevante."
        )
    if risk_key == "moderate":
        return (
            "No se identificaron vulnerabilidades críticas ni de severidad alta. Los hallazgos son de severidad media "
            "y corresponden mayormente a endurecimiento (hardening) recomendado."
        )
    return (
        "No se identificaron vulnerabilidades explotables. Los hallazgos son de severidad baja/informativa y "
        "corresponden a higiene y endurecimiento (hardening); su corrección reduce la superficie de ataque sin "
        "ser urgente. El objetivo evaluado muestra una postura de seguridad sólida."
    )


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts
