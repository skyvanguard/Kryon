"""Findings table section — sortable table with severity badges and MITRE tags."""

from __future__ import annotations

from kryon.intelligence.models import Finding

# Spanish severity labels for the badges (uppercase, matching the .sev-badge style).
_SEV_ES = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO"}


def render_findings_table(findings: list[Finding], include_evidence: bool = True) -> str:
    """Render a compact summary table (fits the page) + a full-width detail card per finding.

    The old single 10-column table (incl. Evidence <pre> + Remediation long text) overflowed the PDF
    page width and clipped the right columns. Split it: a narrow summary table for the at-a-glance view,
    then one readable card per finding with the long-form evidence/remediation/MITRE.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 5))

    # 1. Compact summary table — 6 narrow columns that fit portrait A4.
    # Only show CVE / CVSS columns when at least one finding populates them — otherwise they are
    # all "-" and just waste horizontal space (which forced the headers to wrap to "C/V/S/S").
    has_cve = any(f.cve for f in sorted_findings)
    has_cvss = any(f.cvss_score for f in sorted_findings)

    # Column model: (header, width%, cell-fn). Widths re-balance to whatever columns are present.
    cols: list[tuple[str, int, object]] = [
        ("#", 6, lambda i, f: str(i)),
        ("Severidad", 16, lambda i, f: f'<span class="sev-badge {f.severity.value}">{_SEV_ES.get(f.severity.value, f.severity.value.upper())}</span>'),
        ("Hallazgo", 0, lambda i, f: _escape(f.title)),
        ("Activo", 26, lambda i, f: f"<code>{_escape(f.affected_asset)}</code>"),
    ]
    if has_cve:
        cols.append(("CVE", 14, lambda i, f: f.cve.cve_id if f.cve else "-"))
    if has_cvss:
        cols.append(("CVSS", 8, lambda i, f: f"{f.cvss_score:.1f}" if f.cvss_score else "-"))
    # "Hallazgo" (width 0) absorbs the remaining width.
    used = sum(w for _, w, _ in cols)
    cols = [(h, (100 - used if w == 0 else w), fn) for h, w, fn in cols]

    colgroup = "".join(f'<col style="width:{w}%">' for _, w, _ in cols)
    header = "".join(f"<th>{h}</th>" for h, _, _ in cols)
    summary_rows = []
    for i, f in enumerate(sorted_findings, 1):
        tds = "".join(f"<td>{fn(i, f)}</td>" for _, _, fn in cols)
        summary_rows.append(f'<tr class="severity-{f.severity.value}">{tds}</tr>')
    summary = f"""
    <div class="findings-section">
        <h2>Resumen de hallazgos</h2>
        <table class="findings-table summary">
            <colgroup>{colgroup}</colgroup>
            <thead><tr>{header}</tr></thead>
            <tbody>{"".join(summary_rows)}</tbody>
        </table>
    </div>"""

    # 2. One detail card per finding — full width, long-form fields wrap freely.
    cards = []
    for i, f in enumerate(sorted_findings, 1):
        mitre = ", ".join(m.technique_id for m in f.mitre[:5]) if f.mitre else "-"
        cve_str = f.cve.cve_id if f.cve else "-"
        meta = (
            f"<strong>Activo:</strong> <code>{_escape(f.affected_asset)}</code> &nbsp;·&nbsp; "
            f"<strong>CVE:</strong> {cve_str} &nbsp;·&nbsp; "
            f"<strong>Fuente:</strong> {_escape(f.tool_source or '-')} &nbsp;·&nbsp; "
            f"<strong>MITRE:</strong> {mitre}"
        )
        evidence_block = ""
        if include_evidence and f.evidence:
            evidence_block = (
                f"<p class=\"label\">Evidencia</p><pre class=\"evidence\">{_escape(f.evidence[:1200])}</pre>"
            )
        remediation_block = ""
        if f.remediation:
            remediation_block = f"<p class=\"label\">Remediación</p><p>{_escape(f.remediation)}</p>"
        cards.append(f"""
        <div class="finding-card severity-{f.severity.value}">
            <h3>{i}. <span class="sev-badge {f.severity.value}">{_SEV_ES.get(f.severity.value, f.severity.value.upper())}</span> {_escape(f.title)}</h3>
            <p>{_escape(f.description)}</p>
            <p class="meta">{meta}</p>
            {evidence_block}
            {remediation_block}
        </div>""")

    detail = f"""
    <div class="findings-detail">
        <h2>Detalle de hallazgos</h2>
        {"".join(cards)}
    </div>"""

    return summary + detail


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
