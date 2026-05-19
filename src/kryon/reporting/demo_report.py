"""Demo-oriented report renderer for britimp-style engagements.

Minimal entry point that takes a plain list of findings (dicts, no
pydantic required) + engagement context and produces an executive PDF.

Usage:

    from kryon.reporting.demo_report import render_demo_report

    html_path, pdf_path = render_demo_report(
        findings=[
            {"cwe": "CWE-521", "severity": "CRITICAL", "host": "192.168.1.10",
             "rule_id": "sshd-permit-root-login",
             "message": "SSH allows root login with password.",
             "evidence": "PermitRootLogin yes\\nPasswordAuthentication yes",
             "remediation": "Disable root login and require public-key auth."},
            ...
        ],
        context={
            "client_name": "britimp",
            "engagement_id": "bcp-demo-2026-04-15",
            "target_scope": "192.168.1.0/24",
            "auditor": "SkyVanguard / Kryon",
        },
        output_dir="/workspace/reports",
    )

The generated PDF is the file we hand to BCP. No LLM required.
"""

from __future__ import annotations

import html as _html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_EXECUTIVE_CSS = """
@page { size: A4; margin: 2cm 2.2cm; }
body { background: #fff; color: #1a202c;
  font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', Arial, sans-serif;
  max-width: 1000px; margin: 0 auto; padding: 0; line-height: 1.55; }
h1 { color: #1a365d; font-size: 28px; margin-bottom: 4px; }
h2 { color: #2d3748; border-bottom: 2px solid #e2e8f0;
  padding-bottom: 6px; margin-top: 28px; }
h3 { color: #2d3748; margin-top: 18px; }
.header { border-bottom: 3px solid #1a365d; padding-bottom: 18px; margin-bottom: 22px; }
.header .sub { color: #4a5568; font-size: 15px; margin-top: 6px; }
.header .meta { color: #718096; font-size: 12px; margin-top: 10px; }
.summary { background: #f7fafc; border-left: 4px solid #1a365d;
  padding: 16px 20px; margin: 20px 0; border-radius: 4px; }
.kpi-row { display: flex; gap: 14px; margin: 18px 0; }
.kpi { flex: 1; background: #f7fafc; padding: 14px 18px;
  border-radius: 6px; border-top: 3px solid #1a365d; }
.kpi .label { font-size: 11px; color: #718096;
  text-transform: uppercase; letter-spacing: 0.06em; }
.kpi .value { font-size: 28px; font-weight: 600; color: #1a365d; }
.findings-table { width: 100%; border-collapse: collapse;
  margin: 15px 0; font-size: 13px; }
.findings-table th { background: #edf2f7; color: #2d3748;
  padding: 10px; text-align: left; font-weight: 600; }
.findings-table td { padding: 10px; border-bottom: 1px solid #e2e8f0;
  vertical-align: top; }
.sev { display: inline-block; padding: 2px 10px; border-radius: 11px;
  font-size: 11px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.04em; }
.sev.critical { background: #fed7d7; color: #822727; }
.sev.high     { background: #feebc8; color: #7b341e; }
.sev.medium   { background: #fefcbf; color: #744210; }
.sev.low      { background: #c6f6d5; color: #22543d; }
.sev.info     { background: #bee3f8; color: #2a4365; }
.finding-card { margin: 16px 0; padding: 16px 20px;
  border-left: 4px solid #a0aec0; background: #fafbfc;
  border-radius: 4px; page-break-inside: avoid; }
.finding-card.critical { border-left-color: #822727; }
.finding-card.high     { border-left-color: #7b341e; }
.finding-card.medium   { border-left-color: #744210; }
.finding-card.low      { border-left-color: #22543d; }
.finding-card .title { font-weight: 600; font-size: 15px; margin-bottom: 6px; }
.finding-card .meta { color: #718096; font-size: 12px; margin-bottom: 10px; }
.finding-card pre.evidence {
  background: #1a202c; color: #e2e8f0; padding: 10px;
  border-radius: 4px; font-size: 12px; overflow-x: auto;
  font-family: 'Consolas', 'Monaco', monospace;
  page-break-inside: avoid; white-space: pre-wrap; }
.finding-card .remediation {
  background: #ebf4ff; border-left: 3px solid #3182ce;
  padding: 10px 14px; margin-top: 10px; border-radius: 3px;
  font-size: 13px; }
.footer { margin-top: 40px; padding-top: 16px;
  border-top: 1px solid #e2e8f0; color: #718096;
  font-size: 11px; text-align: center; }
"""


def _normalise_severity(raw: str) -> str:
    s = (raw or "").upper().strip()
    if s in _SEVERITY_RANK:
        return s
    alias = {"CRIT": "CRITICAL", "ERROR": "HIGH", "WARN": "MEDIUM", "WARNING": "MEDIUM", "NONE": "INFO"}
    return alias.get(s, "INFO")


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    c: Counter[str] = Counter()
    for f in findings:
        c[_normalise_severity(f.get("severity", ""))] += 1
    return {k: c.get(k, 0) for k in _SEVERITY_RANK}


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(_normalise_severity(f.get("severity", "")), 99),
            f.get("host", ""),
            f.get("rule_id", ""),
        ),
    )


def _render_engagement_verdict(verdict_info: dict | None) -> str:
    """F122 — Render the F118 engagement verdict as an HTML banner so
    the operator/client sees SATISFIED/PARTIAL/NOT_MET in the report,
    not just in the console output."""
    if not verdict_info:
        return ""
    verdict = str(verdict_info.get("verdict", "")).lower()
    label = verdict.upper() or "—"
    reasoning = _html.escape(str(verdict_info.get("reasoning", "")))
    goal_raw = _html.escape(str(verdict_info.get("goal_raw", "")))
    goal_kind = _html.escape(str(verdict_info.get("goal_kind", "")))
    evidence_count = int(verdict_info.get("evidence_count", 0))
    color = {
        "satisfied": ("#22543d", "#c6f6d5"),
        "partial": ("#744210", "#fefcbf"),
        "not_met": ("#822727", "#fed7d7"),
    }.get(verdict, ("#2a4365", "#bee3f8"))
    return (
        f'<div class="verdict-banner" style="margin:20px 0;padding:14px 18px;'
        f'border-left:5px solid {color[0]};background:{color[1]};border-radius:4px;">'
        f'<div style="font-size:11px;color:{color[0]};text-transform:uppercase;'
        f'letter-spacing:0.08em;font-weight:600;">Veredicto del engagement</div>'
        f'<div style="font-size:22px;color:{color[0]};font-weight:700;margin:4px 0;">'
        f"{label}</div>"
        f'<div style="font-size:13px;color:#2d3748;">{reasoning}</div>'
        f'<div style="font-size:11px;color:#718096;margin-top:8px;">'
        f"Objetivo declarado ({goal_kind}): <em>{goal_raw}</em> · "
        f"{evidence_count} evidencia(s) recolectada(s)</div></div>"
    )


def _build_executive_summary(findings: list[dict], context: dict, counts: dict[str, int]) -> str:
    """Plain-text summary, deterministic — no LLM needed for the demo PDF."""
    total = len(findings)
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    if total == 0:
        return "No se detectaron hallazgos durante la evaluación."
    lines: list[str] = []
    lines.append(
        f"Se identificaron <strong>{total} hallazgos</strong> en el alcance "
        f"<code>{_html.escape(context.get('target_scope', ''))}</code>."
    )
    if critical:
        lines.append(
            f'<strong class="sev critical" style="padding:2px 8px;">'
            f"{critical} CRITICAL</strong> requieren remediación inmediata "
            f"(impacto potencial: exposición de servicios, credenciales "
            f"débiles, o configuración que habilita escalación)."
        )
    if high:
        lines.append(
            f'<strong class="sev high" style="padding:2px 8px;">'
            f"{high} HIGH</strong> deben resolverse en la ventana de "
            f"remediación estándar del cliente."
        )
    hosts = sorted({f.get("host", "") for f in findings if f.get("host")})
    if hosts:
        lines.append(
            f"Hosts afectados: {len(hosts)} "
            f"({', '.join(_html.escape(h) for h in hosts[:6])}"
            f"{'...' if len(hosts) > 6 else ''})."
        )
    lines.append(
        "El detalle técnico con evidencia y pasos de remediación se "
        "presenta en las secciones siguientes. Las acciones marcadas "
        "[DRY-RUN] en el log fueron simuladas, no aplicadas."
    )
    return "<p>" + "</p><p>".join(lines) + "</p>"


def _finding_card_html(finding: dict) -> str:
    sev = _normalise_severity(finding.get("severity", ""))
    cls = sev.lower()
    host = _html.escape(finding.get("host", ""))
    cwe = _html.escape(finding.get("cwe", ""))
    rule = _html.escape(finding.get("rule_id", ""))
    title = _html.escape(finding.get("message") or finding.get("title") or rule)
    evidence = _html.escape(finding.get("evidence", ""))
    remediation = _html.escape(finding.get("remediation", ""))

    meta_parts: list[str] = []
    if cwe:
        meta_parts.append(cwe)
    if host:
        meta_parts.append(host)
    if rule:
        meta_parts.append(f"rule: {rule}")
    meta = " · ".join(meta_parts)

    evidence_html = f'<pre class="evidence">{evidence}</pre>' if evidence else ""
    remediation_html = (
        f'<div class="remediation"><strong>Remediación:</strong> {remediation}</div>' if remediation else ""
    )
    return f"""
    <div class="finding-card {cls}">
      <div class="title"><span class="sev {cls}">{sev}</span> {title}</div>
      <div class="meta">{meta}</div>
      {evidence_html}
      {remediation_html}
    </div>
    """


def _kpi_row_html(counts: dict[str, int], total: int) -> str:
    cells = [("Total", total)]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cells.append((sev, counts.get(sev, 0)))
    html = '<div class="kpi-row">'
    for label, value in cells:
        html += f'<div class="kpi"><div class="label">{label}</div><div class="value">{value}</div></div>'
    html += "</div>"
    return html


def render_html(findings: list[dict], context: dict) -> str:
    """Render the HTML document. Deterministic — no LLM."""
    ctx = dict(context or {})
    ctx.setdefault("client_name", "")
    ctx.setdefault("engagement_id", "")
    ctx.setdefault("target_scope", "")
    ctx.setdefault("auditor", "SkyVanguard / Kryon")
    ctx.setdefault("date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    findings_sorted = _sorted_findings(findings)
    counts = _severity_counts(findings_sorted)
    total = len(findings_sorted)
    summary = _build_executive_summary(findings_sorted, ctx, counts)

    # Findings table (quick overview)
    rows: list[str] = []
    for i, f in enumerate(findings_sorted, 1):
        sev = _normalise_severity(f.get("severity", ""))
        cls = sev.lower()
        rows.append(
            f"<tr>"
            f"<td>{i}</td>"
            f'<td><span class="sev {cls}">{sev}</span></td>'
            f"<td>{_html.escape(f.get('cwe', ''))}</td>"
            f"<td>{_html.escape(f.get('host', ''))}</td>"
            f"<td>{_html.escape(f.get('rule_id', ''))}</td>"
            f"<td>{_html.escape((f.get('message') or '')[:120])}</td>"
            f"</tr>"
        )
    table_html = "".join(rows) or (
        '<tr><td colspan="6" style="text-align:center;color:#718096;">Sin hallazgos</td></tr>'
    )

    # Finding cards (detailed)
    cards_html = "".join(_finding_card_html(f) for f in findings_sorted)

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Kryon — Reporte de evaluación {_html.escape(ctx["engagement_id"])}</title>
<style>{_EXECUTIVE_CSS}</style></head><body>
<div class="header">
  <h1>Reporte de evaluación de seguridad</h1>
  <div class="sub">Cliente: <strong>{_html.escape(ctx["client_name"]) or "—"}</strong>
    · Alcance: <code>{_html.escape(ctx["target_scope"]) or "—"}</code></div>
  <div class="meta">Engagement: {_html.escape(ctx["engagement_id"]) or "—"}
    · Generado: {_html.escape(ctx["date"])}
    · Auditor: {_html.escape(ctx["auditor"])}</div>
</div>

<h2>Resumen ejecutivo</h2>
<div class="summary">{summary}</div>
{_render_engagement_verdict(ctx.get("engagement_verdict"))}
{_kpi_row_html(counts, total)}

<h2>Índice de hallazgos</h2>
<table class="findings-table">
<thead><tr>
<th>#</th><th>Severidad</th><th>CWE</th><th>Host</th>
<th>Regla</th><th>Descripción</th>
</tr></thead>
<tbody>{table_html}</tbody>
</table>

<h2>Detalle técnico</h2>
{cards_html}

<div class="footer">
  Reporte generado por Kryon — SkyVanguard, Asunción, Paraguay. · Confidencial.
</div>
</body></html>
"""


def render_demo_report(
    findings: list[dict],
    context: dict | None = None,
    output_dir: str | Path = "./reports",
    *,
    filename_stem: str | None = None,
    write_html: bool = True,
    write_pdf: bool = True,
) -> dict[str, Path]:
    """Render the engagement report. Returns {"html": path, "pdf": path}.

    PDF generation requires the `reporting` optional extra (weasyprint).
    HTML-only output works without extras.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    context = context or {}
    stem = (filename_stem or f"kryon-{context.get('engagement_id', 'report')}" or "kryon-report").replace(" ", "-")

    html_doc = render_html(findings, context)
    paths: dict[str, Path] = {}

    if write_html:
        html_path = out_dir / f"{stem}.html"
        html_path.write_text(html_doc, encoding="utf-8")
        paths["html"] = html_path

    # F202.X — KRYON_SKIP_PDF=1 short-circuit. Util en operador Windows
    # sin GTK3 runtime para evitar el warning ruidoso en cada engage.
    import os as _os

    if write_pdf and _os.environ.get("KRYON_SKIP_PDF", "").strip().lower() in ("1", "true", "yes"):
        write_pdf = False
        paths["pdf_skipped"] = Path("KRYON_SKIP_PDF=1 set; HTML + JSON only")

    if write_pdf:
        # F202.X — WeasyPrint en Windows requiere GTK3 runtime DLLs
        # (libgobject-2.0-0, pango, cairo, fontconfig) que no vienen con
        # `pip install weasyprint`. Sin las DLLs, el import dispara OSError
        # NO ImportError — el except ImportError no lo capturaba y rompia
        # toda la Fase 6 del engage. Capturamos ambos + cualquier fallo
        # en write_pdf (pango font discovery puede fallar tambien).
        # HTML + JSON ya estan escritos antes de llegar aca, asi que la
        # engagement no se pierde — solo el PDF falta.
        try:
            from weasyprint import HTML  # type: ignore
        except ImportError:
            paths["pdf_error"] = Path(
                "install the 'reporting' extra: pip install 'kryon[reporting]'"
            )
        except OSError as e:
            # Most common: Windows + no GTK runtime installed.
            paths["pdf_error"] = Path(
                f"WeasyPrint native deps missing ({e}). "
                "On Windows: install GTK3 runtime from "
                "https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases "
                "OR set KRYON_SKIP_PDF=1 to silence. HTML + JSON reports were generated."
            )
        else:
            pdf_path = out_dir / f"{stem}.pdf"
            try:
                HTML(string=html_doc).write_pdf(str(pdf_path))
                paths["pdf"] = pdf_path
            except (OSError, Exception) as e:  # noqa: BLE001
                # write_pdf can fail mid-render on font discovery, missing
                # locales, or any of the GTK pipeline pieces that imported
                # OK but choke at runtime.
                paths["pdf_error"] = Path(
                    f"WeasyPrint render failed ({type(e).__name__}: {e}). "
                    "HTML + JSON reports were generated successfully."
                )

    # Side-effect: drop the raw findings JSON alongside for audit.
    json_path = out_dir / f"{stem}.findings.json"
    json_path.write_text(
        json.dumps({"context": context, "findings": findings}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    paths["json"] = json_path

    return paths
