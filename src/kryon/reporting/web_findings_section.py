"""Web pentest findings section for multi-framework PDF (F60).

Converts a web-pentest JSON artifact (produced by F61 /webpentest) into
a section suitable for embedding into the compliance PDF template
(F27.5 + the future F44 multi-framework consolidator).

This module deliberately does NOT render PDFs directly — it produces a
normalized dict that the jinja template in
``src/kryon/reporting/compliance_pdf.py`` consumes, so the two
pipelines share layout + bilingual styling.

API:
    load_webpentest_report(path) -> WebReportData
    render_web_section_html(data) -> str (HTML fragment)
    findings_as_checkresult_dicts(data) -> list[dict]  # for F44 merge

The CheckResult-compatible dicts are the bridge to the existing
compliance flow: the F44 consolidator will sum them with the regular
compliance results to produce a unified multi-framework PDF.
"""

from __future__ import annotations

import html as _html
import json
from dataclasses import dataclass
from pathlib import Path

from kryon.compliance.cwe_mapping import frameworks_for_cwe


@dataclass(frozen=True)
class WebFinding:
    """Normalized web finding record loaded from the /webpentest JSON."""

    cwe_id: str
    probe_id: str
    severity: str
    status: str  # CONFIRMED | CANDIDATE | FALSE_POSITIVE
    title: str
    url: str
    evidence: str
    remediation: str
    compliance_citations: tuple[str, ...] = ()


@dataclass(frozen=True)
class WebReportData:
    """Parsed web-pentest report ready for section rendering."""

    target: str
    repro_hash: str
    llm_mode: str
    findings: tuple[WebFinding, ...]
    stats: dict
    duration_s: float


def load_webpentest_report(path: str | Path) -> WebReportData:
    """Load the JSON emitted by `/webpentest` and enrich each finding
    with its compliance citations via F59."""
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"web report not found: {src}")

    payload = json.loads(src.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    findings_raw = payload.get("findings", [])

    enriched: list[WebFinding] = []
    for f in findings_raw:
        cwe = f.get("cwe_id", "")
        tags = frameworks_for_cwe(cwe)
        citations = tuple(tags.citations()) if tags else ()
        enriched.append(WebFinding(
            cwe_id=cwe,
            probe_id=f.get("probe_id", ""),
            severity=f.get("severity", "MEDIUM"),
            status=f.get("status", "CANDIDATE"),
            title=f.get("title", ""),
            url=f.get("url", ""),
            evidence=f.get("evidence", ""),
            remediation=f.get("remediation", ""),
            compliance_citations=citations,
        ))

    return WebReportData(
        target=payload.get("target", ""),
        repro_hash=payload.get("repro_hash", ""),
        llm_mode=summary.get("llm_mode", "noop"),
        findings=tuple(enriched),
        stats={
            "plan_size": summary.get("plan_size", 0),
            "probes_executed": summary.get("probes_executed", 0),
            "findings_total": summary.get("findings_total", 0),
            "gaps_total": summary.get("gaps_total", 0),
            "llm_candidates": summary.get("llm_candidates", 0),
            "by_status": summary.get("by_status", {}),
            "by_severity": summary.get("by_severity", {}),
            "by_cwe": summary.get("by_cwe", {}),
        },
        duration_s=float(summary.get("duration_s", 0.0)),
    )


# Severity ordering for presentation
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _order_key(f: WebFinding) -> tuple:
    return (_SEV_ORDER.get(f.severity, 9), f.cwe_id, f.url)


def render_web_section_html(data: WebReportData) -> str:
    """Return an HTML fragment for inclusion in the compliance PDF.

    Styling classes match compliance_pdf.py so the PDF renderer
    (weasyprint) picks up the same fonts / colors / table borders.
    """
    esc = _html.escape

    sev_badge = {
        "CRITICAL": '<span class="badge-critical">CRITICAL</span>',
        "HIGH":     '<span class="badge-high">HIGH</span>',
        "MEDIUM":   '<span class="badge-medium">MEDIUM</span>',
        "LOW":      '<span class="badge-low">LOW</span>',
        "INFO":     '<span class="badge-info">INFO</span>',
    }
    status_badge = {
        "CONFIRMED":      '<span class="badge-fail">CONFIRMED</span>',
        "CANDIDATE":      '<span class="badge-warn">CANDIDATE</span>',
        "FALSE_POSITIVE": '<span class="badge-pass">FALSE POSITIVE</span>',
    }

    rows: list[str] = []
    for f in sorted(data.findings, key=_order_key):
        cites = "<br>".join(esc(c) for c in f.compliance_citations) or "—"
        rows.append(f"""
        <tr>
          <td>{esc(f.cwe_id)}</td>
          <td>{sev_badge.get(f.severity, esc(f.severity))}</td>
          <td>{status_badge.get(f.status, esc(f.status))}</td>
          <td>{esc(f.title)}</td>
          <td class="url">{esc(f.url)}</td>
          <td class="citations">{cites}</td>
        </tr>""")

    stats = data.stats
    stats_summary = (
        f"Plan: {stats.get('plan_size', 0)} probes • "
        f"Ejecutados: {stats.get('probes_executed', 0)} • "
        f"Hallazgos: {stats.get('findings_total', 0)} • "
        f"Gaps: {stats.get('gaps_total', 0)} • "
        f"LLM candidates: {stats.get('llm_candidates', 0)} ({data.llm_mode})"
    )

    return f"""
<section class="web-findings">
  <h2>Web Application Dynamic Findings</h2>
  <p class="meta">
    <strong>Target:</strong> {esc(data.target)}<br>
    <strong>Duración:</strong> {data.duration_s:.1f}s<br>
    <strong>Repro hash:</strong> <code>{esc(data.repro_hash[:16])}…</code><br>
    <strong>Modo:</strong> {esc(data.llm_mode)}
  </p>
  <p class="stats">{esc(stats_summary)}</p>
  <table class="findings-table">
    <thead>
      <tr>
        <th>CWE</th>
        <th>Severidad</th>
        <th>Estado</th>
        <th>Título</th>
        <th>URL</th>
        <th>Cumplimiento / Normativa</th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>
""".strip()


def findings_as_checkresult_dicts(data: WebReportData) -> list[dict]:
    """Convert web findings into CheckResult-compatible dicts.

    The F44 multi-framework consolidator will merge these with the
    compliance CheckResult records so a single PDF reports both
    streams.  Each dict follows ``CheckResult.to_json_reproducible``:

        control_id, control_title, section, verdict, evidence_command,
        evidence_stdout, evidence_stderr, evidence_parsed,
        remediation_static, severity, host
    """
    status_to_verdict = {
        "CONFIRMED": "FAIL",
        "CANDIDATE": "FAIL",          # treat as fail; narrative says 'needs manual confirm'
        "FALSE_POSITIVE": "PASS",
    }
    out: list[dict] = []
    for f in sorted(data.findings, key=_order_key):
        out.append({
            "control_id": f.probe_id,
            "control_title": f.title,
            "section": f.cwe_id,
            "verdict": status_to_verdict.get(f.status, "FAIL"),
            "evidence_command": f.url,
            "evidence_stdout": f.evidence[:2048],
            "evidence_stderr": "",
            "evidence_parsed": {
                "cwe_id": f.cwe_id,
                "status": f.status,
                "compliance_citations": list(f.compliance_citations),
                "probe_id": f.probe_id,
            },
            "remediation_static": f.remediation,
            "severity": f.severity,
            "host": data.target,
        })
    return out
