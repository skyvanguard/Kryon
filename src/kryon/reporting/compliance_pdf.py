"""PCI-DSS v4 compliance audit PDF generator (F15.1).

Architecture rules (non-negotiable, see docs/F15_0_INVENTORY_AND_GAPS.md):
  - Verdicts come from CheckResult (deterministic). LLM never modifies.
  - Evidence (command, stdout, stderr) comes from CheckResult raw. LLM never modifies.
  - Remediation_static string comes from the check module. LLM never modifies.
  - LLM may generate `context_prose` and `remediation_prose` for the narrative
    sections, AFTER reading CheckResult. These are rendered in visibly-distinct
    blocks with a clear LLM watermark.

Consumes: list[CheckResult] + optional dict[control_id -> {context_prose,
remediation_prose}] keyed from an LLM narrator step.

Produces: self-contained HTML (+ optional weasyprint PDF).
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_VERDICT_COLOR = {
    "FAIL": "#c1272d",
    "PASS": "#2a9d3a",
    "N/A": "#8a8a8a",
    "ERROR": "#d19500",
}


def _esc(s: str) -> str:
    return html.escape(str(s))


def _sort_results(results: list[dict]) -> list[dict]:
    """Sort by verdict (FAIL first) then severity then control_id."""
    return sorted(
        results,
        key=lambda r: (
            0 if r["verdict"] == "FAIL" else 1 if r["verdict"] == "ERROR" else 2,
            _SEV_ORDER.get(r.get("severity", "INFO"), 9),
            r["section"],
            r["control_id"],
        ),
    )


def _css() -> str:
    return """
    @page { size: A4; margin: 18mm 14mm 22mm 14mm;
            @bottom-center {
                content: "PCI-DSS v4 Compliance Audit — page " counter(page) " / " counter(pages);
                font-size: 8pt; color: #666;
            }
            @bottom-left { content: var(--hash); font-size: 7pt; color: #999; font-family: monospace; }
    }
    body { font-family: "Helvetica Neue", Arial, sans-serif; color: #222; font-size: 10.5pt; line-height: 1.4; }
    h1 { font-size: 22pt; margin: 0 0 4pt 0; }
    h2 { font-size: 14pt; margin: 18pt 0 6pt 0; border-bottom: 1px solid #ccc; padding-bottom: 2pt; }
    h3 { font-size: 11pt; margin: 12pt 0 4pt 0; }
    .cover-meta { color: #666; font-size: 9.5pt; margin-bottom: 14pt; }
    .repro-hash { font-family: monospace; font-size: 8.5pt; color: #555; word-break: break-all; }
    .summary-table { border-collapse: collapse; width: 100%; margin: 8pt 0 12pt 0; font-size: 10pt; }
    .summary-table th, .summary-table td { border: 1px solid #ddd; padding: 5pt 7pt; text-align: left; }
    .summary-table th { background: #f2f2f2; font-weight: 600; }
    .verdict-badge { display: inline-block; padding: 1pt 7pt; border-radius: 3pt; color: #fff; font-weight: 700; font-size: 9.5pt; letter-spacing: 0.4pt; }
    .finding-card { page-break-inside: avoid; border: 1px solid #ccc; border-left: 4pt solid #c1272d; border-radius: 3pt; margin: 10pt 0; padding: 8pt 10pt; }
    .finding-card.verdict-PASS { border-left-color: #2a9d3a; }
    .finding-card.verdict-NA   { border-left-color: #8a8a8a; }
    .finding-card.verdict-ERROR { border-left-color: #d19500; }
    .finding-head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4pt; }
    .finding-title { font-weight: 700; }
    .finding-meta { font-size: 9pt; color: #666; margin-bottom: 6pt; }
    .section-block { margin: 6pt 0; }
    .section-label { font-weight: 600; font-size: 9.5pt; color: #333; display: block; margin-bottom: 2pt; }
    /* Deterministic audit block — default styling, plain */
    .det-block { background: #fafafa; border: 1px solid #e0e0e0; padding: 6pt 8pt; font-size: 9.5pt; border-radius: 2pt; }
    .det-block code { font-family: "Consolas", "Courier New", monospace; font-size: 9pt; }
    /* LLM narrative block — visually distinct + watermark */
    .llm-block { background: #fff8e5; border: 1px dashed #e0a500; padding: 6pt 8pt; border-radius: 2pt; position: relative; font-size: 9.8pt; font-style: italic; margin: 4pt 0; }
    .llm-watermark { display: inline-block; background: #e0a500; color: #fff; font-size: 8pt; padding: 1pt 5pt; border-radius: 2pt; font-weight: 700; letter-spacing: 0.6pt; font-style: normal; margin-right: 6pt; text-transform: uppercase; }
    .separator-notice { background: #fff4d5; border-left: 3pt solid #e0a500; padding: 6pt 10pt; font-size: 9.5pt; margin: 10pt 0; }
    pre.evidence { background: #1e1e1e; color: #e8e8e8; font-family: "Consolas", monospace; font-size: 8.5pt; padding: 6pt 8pt; border-radius: 2pt; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 160pt; }
    .appendix h2 { margin-top: 24pt; }
    .footer-note { font-size: 8.5pt; color: #777; margin-top: 20pt; border-top: 1px solid #eee; padding-top: 6pt; }
    """


def _verdict_badge(verdict: str) -> str:
    color = _VERDICT_COLOR.get(verdict, "#555")
    return f'<span class="verdict-badge" style="background:{color}">{_esc(verdict)}</span>'


def _summary_table(results: list[dict]) -> str:
    rows = []
    for r in _sort_results(results):
        rows.append(
            "<tr>"
            f"<td><code>{_esc(r['control_id'])}</code></td>"
            f"<td>{_esc(r.get('control_title', ''))}</td>"
            f"<td>{_esc(r.get('section', ''))}</td>"
            f"<td>{_verdict_badge(r['verdict'])}</td>"
            f"<td>{_esc(r.get('severity', ''))}</td>"
            "</tr>"
        )
    return (
        '<table class="summary-table">'
        "<thead><tr><th>Control</th><th>Título</th><th>Sección</th>"
        "<th>Veredicto</th><th>Severidad</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _finding_card(r: dict, narrative: dict | None) -> str:
    verdict = r["verdict"]
    css_class = f"verdict-{verdict.replace('/', '')}"
    ev = r.get("evidence_parsed") or {}
    parsed_json = json.dumps(ev, indent=2, ensure_ascii=False)

    # Context and Remediation: LLM-generated prose wrapped with watermark.
    ctx_prose = (narrative or {}).get("context_prose") or ""
    rem_prose = (narrative or {}).get("remediation_prose") or ""
    ctx_block = (
        f'<div class="llm-block"><span class="llm-watermark">LLM Narrativa</span>{_esc(ctx_prose)}</div>'
        if ctx_prose.strip()
        else ""
    )
    rem_block = (
        f'<div class="llm-block"><span class="llm-watermark">LLM Narrativa</span>{_esc(rem_prose)}</div>'
        if rem_prose.strip()
        else ""
    )

    host = _esc(r.get("host", "localhost"))
    cmd = _esc(r.get("evidence_command", ""))
    stdout = _esc(r.get("evidence_stdout", "")[:2000])
    stderr = _esc(r.get("evidence_stderr", "")[:512])

    return f"""
    <div class="finding-card {css_class}">
      <div class="finding-head">
        <span class="finding-title">PCI {r["control_id"]} — {_esc(r.get("control_title", ""))}</span>
        {_verdict_badge(verdict)}
      </div>
      <div class="finding-meta">Sección {r["section"]} · Severidad {r.get("severity", "")} · Host {host}</div>

      <div class="section-block">
        <span class="section-label">Evidencia determinística</span>
        <div class="det-block">
          <div><strong>Comando ejecutado:</strong> <code>{cmd}</code></div>
          <div><strong>Hallazgos estructurados:</strong></div>
          <pre class="evidence">{_esc(parsed_json)}</pre>
        </div>
      </div>

      <div class="section-block">
        <span class="section-label">Remediación determinística (texto de la regla)</span>
        <div class="det-block">{_esc(r.get("remediation_static", ""))}</div>
      </div>

      {f'<div class="section-block"><span class="section-label">Contexto (LLM)</span>{ctx_block}</div>' if ctx_block else ""}
      {f'<div class="section-block"><span class="section-label">Detalle de remediación (LLM)</span>{rem_block}</div>' if rem_block else ""}
    </div>
    """


def _appendix_evidence(r: dict) -> str:
    return f"""
    <h3>PCI {_esc(r["control_id"])} — {_esc(r.get("control_title", ""))}</h3>
    <div class="section-block">
      <span class="section-label">Comando</span>
      <pre class="evidence">{_esc(r.get("evidence_command", ""))}</pre>
    </div>
    <div class="section-block">
      <span class="section-label">stdout (raw)</span>
      <pre class="evidence">{_esc(r.get("evidence_stdout", ""))}</pre>
    </div>
    <div class="section-block">
      <span class="section-label">stderr (raw)</span>
      <pre class="evidence">{_esc(r.get("evidence_stderr", "") or "(vacío)")}</pre>
    </div>
    """


# Framework metadata for cover page (ES title + EN title + scope description)
_FRAMEWORK_INFO = {
    "pci-dss": {
        "title_es": "Auditoría de cumplimiento PCI-DSS v4.0.1",
        "title_en": "PCI-DSS v4.0.1 Compliance Audit",
        "scope_es": "Secciones 2, 6, 8, 10 (6 controles críticos)",
        "scope_en": "Sections 2, 6, 8, 10 (6 critical controls)",
    },
    "proxmox": {
        "title_es": "Auditoría de hardening Proxmox VE (perfil bancario)",
        "title_en": "Proxmox VE Hardening Audit (banking profile)",
        "scope_es": "7 controles sobre Web UI, SSH, cluster auth, firewall, patches",
        "scope_en": "7 controls covering Web UI, SSH, cluster auth, firewall, patching",
    },
    "ad": {
        "title_es": "Auditoría de hardening Active Directory (perfil bancario)",
        "title_en": "Active Directory Hardening Audit (banking profile)",
        "scope_es": "9 controles LDAP/LDAPS, Kerberos, privilegios, SMB, logging",
        "scope_en": "9 controls covering LDAP/LDAPS, Kerberos, privileges, SMB, logging",
    },
    "active-directory": {
        "title_es": "Auditoría de hardening Active Directory (perfil bancario)",
        "title_en": "Active Directory Hardening Audit (banking profile)",
        "scope_es": "9 controles LDAP/LDAPS, Kerberos, privilegios, SMB, logging",
        "scope_en": "9 controls covering LDAP/LDAPS, Kerberos, privileges, SMB, logging",
    },
    "all": {
        "title_es": "Auditoría de cumplimiento integral — Kryon",
        "title_en": "Kryon Full Compliance Audit",
        "scope_es": "PCI-DSS + Proxmox VE + Active Directory",
        "scope_en": "PCI-DSS + Proxmox VE + Active Directory",
    },
}


def _risk_level(counts: dict[str, int]) -> tuple[str, str]:
    """Aggregate risk label (ES/EN color coded)."""
    fails = counts.get("FAIL", 0)
    errors = counts.get("ERROR", 0)
    if fails >= 4:
        return ("CRÍTICO", "#c1272d")
    if fails >= 2 or (fails + errors) >= 5:
        return ("ALTO", "#d19500")
    if fails >= 1:
        return ("MEDIO", "#b58b00")
    return ("BAJO", "#2a9d3a")


def _detect_framework(results: list[dict]) -> str:
    """Infer framework from control_id prefixes."""
    prefixes = {r["control_id"].split("-")[0].split(".")[0] for r in results}
    if prefixes == {"PVE"}:
        return "proxmox"
    if prefixes == {"AD"}:
        return "ad"
    if prefixes <= {"2", "6", "8", "10"}:
        return "pci-dss"
    return "all"


def render_html(
    results: list[dict],
    *,
    repro_hash: str,
    host: str,
    narratives: dict[str, dict] | None = None,
    audit_date: datetime | None = None,
    framework: str | None = None,
    client_name: str = "",
) -> str:
    """Render the full audit PDF as HTML.

    results: list of CheckResult-like dicts.
    repro_hash: SHA-256 from reproducibility_hash(results).
    narratives: {control_id: {"context_prose": "...", "remediation_prose": "..."}}
    framework: optional override; auto-detected from results otherwise.
    client_name: banking client name (shown on cover).
    """
    audit_date = audit_date or datetime.now()
    narratives = narratives or {}
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in ("PASS", "FAIL", "N/A", "ERROR")}
    total = len(results)
    cards = "\n".join(_finding_card(r, narratives.get(r["control_id"])) for r in _sort_results(results))
    appendix = "\n".join(_appendix_evidence(r) for r in _sort_results(results))
    css = _css().replace("var(--hash)", f'"{repro_hash[:16]}..."')

    fw_key = (framework or _detect_framework(results)).lower()
    fw = _FRAMEWORK_INFO.get(fw_key, _FRAMEWORK_INFO["all"])
    risk_label, risk_color = _risk_level(counts)

    client_line_es = f"Cliente: <strong>{_esc(client_name)}</strong> · " if client_name else ""

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>{_esc(fw["title_es"])} — {_esc(host)} — {audit_date.strftime("%Y-%m-%d")}</title>
<style>{css}
.risk-banner {{
  display:inline-block; padding:4pt 10pt; border-radius:4pt;
  color:#fff; font-weight:700; font-size:10pt; background:{risk_color};
}}
.bilingual-block {{
  background:#f7f7f0; border-left:3pt solid #666; padding:8pt 12pt;
  margin:10pt 0; font-size:9pt; color:#444;
}}
.bilingual-block .en-label {{
  display:inline-block; background:#222; color:#fff; padding:1pt 6pt;
  border-radius:2pt; font-size:7pt; font-weight:700; margin-right:6pt;
}}
</style>
</head><body>

<h1>{fw["title_es"]}</h1>
<div class="cover-meta">
  {client_line_es}Host: <strong>{_esc(host)}</strong> ·
  Fecha / Date: {audit_date.strftime("%Y-%m-%d %H:%M")} ·
  Alcance: {fw["scope_es"]}
</div>
<div class="cover-meta">
  Riesgo agregado / Overall risk:
  <span class="risk-banner">{risk_label}</span>
</div>
<div class="repro-hash">Hash reproducibilidad / Reproducibility hash: {_esc(repro_hash)}</div>

<div class="separator-notice">
  <strong>Separación de responsabilidades / Separation of duties:</strong>
  los <em>veredictos</em> (PASS/FAIL/N/A/ERROR) y la <em>evidencia</em>
  (comando ejecutado + output raw) provienen de motores determinísticos
  reproducibles. Las secciones marcadas
  <span style="background:#e0a500;color:#fff;padding:1pt 4pt;border-radius:2pt;font-size:8pt;font-weight:700;">LLM NARRATIVA</span>
  son prosa explicativa generada por modelo de lenguaje y no modifican los
  veredictos ni la evidencia. Para defensibilidad regulatoria, el auditor
  debe basarse en la evidencia determinística.
</div>

<h2>Resumen ejecutivo</h2>
<p>Se ejecutaron <strong>{total}</strong> controles sobre el host.
Resultados: <strong style="color:{_VERDICT_COLOR["FAIL"]}">{counts["FAIL"]} FAIL</strong>,
<strong style="color:{_VERDICT_COLOR["PASS"]}">{counts["PASS"]} PASS</strong>,
{counts["N/A"]} N/A, {counts["ERROR"]} ERROR.
Nivel de riesgo agregado: <strong style="color:{risk_color}">{risk_label}</strong>.</p>

<div class="bilingual-block">
  <span class="en-label">EN</span>
  <strong>Executive summary.</strong>
  {total} controls executed on the host. Results:
  <strong style="color:{_VERDICT_COLOR["FAIL"]}">{counts["FAIL"]} FAIL</strong>,
  <strong style="color:{_VERDICT_COLOR["PASS"]}">{counts["PASS"]} PASS</strong>,
  {counts["N/A"]} N/A, {counts["ERROR"]} ERROR. Overall risk:
  <strong style="color:{risk_color}">{risk_label}</strong>.
  Framework: {fw["title_en"]}. Scope: {fw["scope_en"]}.
</div>

{_summary_table(results)}

<h2>Hallazgos / Findings</h2>
{cards}

<div class="appendix">
<h2>Apéndice A — Evidencia cruda / Appendix A — Raw evidence</h2>
<p>Comandos ejecutados y output stdout/stderr sin procesar. Permite
reproducir manualmente cada hallazgo / Commands executed and raw
stdout/stderr, enabling manual reproduction of every finding.</p>
{appendix}
</div>

<div class="footer-note">
Este reporte se considera válido únicamente acompañado del artifact JSON cuyo
SHA-256 coincide con <code>{_esc(repro_hash[:32])}...</code>. Cualquier
modificación del JSON invalida este reporte. Generado por Kryon compliance
engine.
<br/>
This report is valid only alongside the JSON artifact whose SHA-256 matches
the hash above. Any modification to the JSON invalidates this report.
</div>

</body></html>
"""


def render_pdf(
    results: list[dict],
    *,
    repro_hash: str,
    host: str,
    output_path: Path,
    narratives: dict[str, dict] | None = None,
    framework: str | None = None,
    client_name: str = "",
) -> Path:
    """Render HTML and attempt PDF via weasyprint.

    If weasyprint is unavailable, writes the HTML next to output_path and
    raises ImportError so the caller can fall back explicitly.
    """
    html_body = render_html(
        results,
        repro_hash=repro_hash,
        host=host,
        narratives=narratives,
        framework=framework,
        client_name=client_name,
    )
    html_path = output_path.with_suffix(".html")
    html_path.write_text(html_body, encoding="utf-8")
    # F202.X — WeasyPrint Windows GTK3 DLLs missing -> OSError, no
    # ImportError. Caller assumes "PDF or raise" contract, asi que
    # re-raisar pero con mensaje claro y manteniendo el HTML escrito.
    try:
        from weasyprint import HTML  # type: ignore
    except (ImportError, OSError):
        raise
    try:
        HTML(string=html_body).write_pdf(str(output_path))
    except (OSError, Exception):  # noqa: BLE001
        raise
    return output_path
