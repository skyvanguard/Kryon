"""Multi-framework compliance report consolidation (F44).

Takes results from multiple compliance frameworks (CIS Ubuntu + Debian + RHEL
+ Docker, PCI-DSS, SWIFT CSP, BCP PY Res. 12/2021, Core Banking, ATM) and
produces a single consolidated bilingual PDF with:

  - Cross-framework executive summary with per-framework risk badges
  - Aggregated FAIL/CRITICAL counts
  - Compliance mapping (same finding → PCI-DSS 10.5 + BCP 12/2021 Art. 25 + SWIFT 2.1)
  - Per-framework detailed sections (cards + evidence appendix)
  - Overall reproducibility hash

Single entrypoint: ``render_multi_framework_html``. Reuses the single-framework
card/appendix rendering from ``compliance_pdf``; this module only adds the
consolidation scaffolding on top.
"""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime
from typing import Any

from kryon.reporting.compliance_pdf import (
    _VERDICT_COLOR,
    _appendix_evidence,
    _css,
    _finding_card,
    _risk_level,
    _sort_results,
    _summary_table,
)

# Per-framework metadata — titles + regulatory mappings for consolidation table.
FRAMEWORK_META: dict[str, dict[str, str]] = {
    "pci-dss-4.0": {
        "title_es": "PCI-DSS v4.0.1",
        "title_en": "PCI-DSS v4.0.1",
        "scope_es": "Estándar de seguridad para datos de tarjeta",
        "maps_to": "PCI Council",
    },
    "swift-csp-2024": {
        "title_es": "SWIFT CSP v2024",
        "title_en": "SWIFT CSP v2024",
        "scope_es": "Controles obligatorios de seguridad SWIFT",
        "maps_to": "SWIFT",
    },
    "bcp-py-res-12-2021": {
        "title_es": "BCP Paraguay Res. 12/2021",
        "title_en": "BCP Paraguay Resolution 12/2021",
        "scope_es": "Requisitos de ciberseguridad para entidades financieras PY",
        "maps_to": "BCP PY / SIB",
    },
    "cis-ubuntu-22.04-l1": {
        "title_es": "CIS Ubuntu 22.04 LTS Level 1",
        "title_en": "CIS Ubuntu 22.04 LTS Level 1",
        "scope_es": "Hardening OS base",
        "maps_to": "CIS",
    },
    "cis-debian-12-l1": {
        "title_es": "CIS Debian 12 Level 1",
        "title_en": "CIS Debian 12 Level 1",
        "scope_es": "Hardening OS base (Debian)",
        "maps_to": "CIS",
    },
    "cis-rhel-9-l1": {
        "title_es": "CIS RHEL 9 Level 1",
        "title_en": "CIS RHEL 9 Level 1",
        "scope_es": "Hardening OS base (RHEL/Rocky/Alma)",
        "maps_to": "CIS",
    },
    "cis-docker-1.6": {
        "title_es": "CIS Docker Benchmark v1.6",
        "title_en": "CIS Docker Benchmark v1.6",
        "scope_es": "Hardening host Docker + daemon + runtime",
        "maps_to": "CIS",
    },
    "cis-windows-server-2022-l1": {
        "title_es": "CIS Windows Server 2022 L1",
        "title_en": "CIS Windows Server 2022 L1",
        "scope_es": "Hardening Windows Server (2019 / 2022)",
        "maps_to": "CIS",
    },
    "core-banking-hardening": {
        "title_es": "Core Banking Hardening (T24/Finacle/Flexcube)",
        "title_en": "Core Banking Hardening (T24/Finacle/Flexcube)",
        "scope_es": "OS+DB+app para T24, Finacle, Flexcube",
        "maps_to": "Vendor + BCP PY",
    },
    "atm-security-bcp-2024": {
        "title_es": "ATM Security (BCP PY 2024)",
        "title_en": "ATM Security (BCP PY 2024)",
        "scope_es": "Hardening red ATM: físico, OS, cripto, operaciones",
        "maps_to": "BCP PY 2024 + PCI PTS",
    },
}


# Cross-framework control alignment — same security requirement expressed
# in different regulatory vocabularies. Used in the compliance mapping
# section of the consolidated report.
CROSS_MAPPINGS: list[dict[str, Any]] = [
    {
        "topic_es": "Registro centralizado de auditoría",
        "topic_en": "Centralized audit logging",
        "frameworks": {
            "pci-dss-4.0": "10.5",
            "bcp-py-res-12-2021": "Art. 25",
            "swift-csp-2024": "6.4",
            "core-banking-hardening": "CBH-6.1",
        },
    },
    {
        "topic_es": "Cifrado de datos en tránsito",
        "topic_en": "Data-in-transit encryption",
        "frameworks": {
            "pci-dss-4.0": "4.2.1",
            "bcp-py-res-12-2021": "Art. 19",
            "swift-csp-2024": "2.5",
            "core-banking-hardening": "CBH-5.5",
            "atm-security-bcp-2024": "ATM-3.1",
        },
    },
    {
        "topic_es": "Segregación de ambientes (prod vs. no-prod)",
        "topic_en": "Environment segregation (prod vs. non-prod)",
        "frameworks": {
            "bcp-py-res-12-2021": "Art. 21",
            "swift-csp-2024": "1.1",
            "core-banking-hardening": "CBH-6.3",
        },
    },
    {
        "topic_es": "Control de acceso privilegiado / break-glass",
        "topic_en": "Privileged access / break-glass",
        "frameworks": {
            "pci-dss-4.0": "7.2",
            "bcp-py-res-12-2021": "Art. 23",
            "swift-csp-2024": "5.1",
            "core-banking-hardening": "CBH-6.4",
        },
    },
    {
        "topic_es": "Respaldo cifrado fuera de sitio",
        "topic_en": "Encrypted off-site backup",
        "frameworks": {
            "pci-dss-4.0": "3.4",
            "bcp-py-res-12-2021": "Art. 24",
            "core-banking-hardening": "CBH-6.7",
        },
    },
    {
        "topic_es": "Autenticación multifactor para admins",
        "topic_en": "MFA for privileged admins",
        "frameworks": {
            "pci-dss-4.0": "8.4",
            "swift-csp-2024": "4.2",
            "bcp-py-res-12-2021": "Art. 22",
        },
    },
]


def _esc(s: Any) -> str:
    return html.escape(str(s))


def _aggregate_counts(results: list[dict]) -> dict[str, int]:
    out = {"PASS": 0, "FAIL": 0, "N/A": 0, "ERROR": 0}
    for r in results:
        v = r.get("verdict", "N/A")
        out[v] = out.get(v, 0) + 1
    return out


def _critical_fail_count(results: list[dict]) -> int:
    return sum(
        1 for r in results
        if r.get("verdict") == "FAIL" and r.get("severity") == "CRITICAL"
    )


def compute_repro_hash(framework_results: dict[str, list[dict]]) -> str:
    """Stable SHA-256 across all frameworks' results (framework_id → results).

    Sort framework_ids + control_ids for determinism.
    """
    buckets: dict[str, list[dict]] = {}
    for fw_id in sorted(framework_results):
        buckets[fw_id] = sorted(
            framework_results[fw_id],
            key=lambda r: r.get("control_id", ""),
        )
    payload = json.dumps(
        buckets,
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _framework_summary_row(fw_id: str, results: list[dict]) -> str:
    meta = FRAMEWORK_META.get(fw_id, {"title_es": fw_id, "maps_to": "—"})
    counts = _aggregate_counts(results)
    risk_label, risk_color = _risk_level(counts)
    crit_fails = _critical_fail_count(results)
    fail_style = (
        f'style="color:{_VERDICT_COLOR["FAIL"]};font-weight:700"'
        if counts["FAIL"] > 0 else ""
    )
    crit_cell = (
        f'<strong style="color:#c1272d">{crit_fails}</strong>'
        if crit_fails > 0 else "0"
    )
    return f"""<tr>
  <td><strong>{_esc(meta["title_es"])}</strong><br/>
      <span style="font-size:8pt;color:#666">{_esc(meta.get("maps_to", ""))}</span></td>
  <td style="text-align:right">{len(results)}</td>
  <td style="text-align:right"><span {fail_style}>{counts["FAIL"]}</span></td>
  <td style="text-align:right">{counts["PASS"]}</td>
  <td style="text-align:right">{counts["N/A"]}</td>
  <td style="text-align:right">{crit_cell}</td>
  <td><span style="display:inline-block;padding:2pt 7pt;border-radius:3pt;color:#fff;font-size:9pt;background:{risk_color}">{risk_label}</span></td>
</tr>"""


def _cross_framework_summary_table(framework_results: dict[str, list[dict]]) -> str:
    rows = "".join(
        _framework_summary_row(fw_id, framework_results[fw_id])
        for fw_id in sorted(framework_results)
    )
    return f"""<table class="summary-table">
<thead><tr>
  <th>Framework</th>
  <th style="text-align:right">Controles / Controls</th>
  <th style="text-align:right">FAIL</th>
  <th style="text-align:right">PASS</th>
  <th style="text-align:right">N/A</th>
  <th style="text-align:right">CRÍTICOS / CRITICAL</th>
  <th>Riesgo / Risk</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _cross_mapping_section(applicable_frameworks: set[str]) -> str:
    """Render the 'same control in different regulations' mapping table.

    Only renders mappings where at least one involved framework is in
    ``applicable_frameworks`` (to avoid showing SWIFT mappings in a
    PCI-only audit, for instance).
    """
    relevant = [
        m for m in CROSS_MAPPINGS
        if set(m["frameworks"]) & applicable_frameworks
    ]
    if not relevant:
        return ""
    rows = []
    for m in relevant:
        refs = []
        for fw_id, control in m["frameworks"].items():
            if fw_id in applicable_frameworks:
                label = FRAMEWORK_META.get(fw_id, {}).get("title_es", fw_id)
                refs.append(f"<strong>{_esc(label)}</strong> {_esc(control)}")
        rows.append(
            f'<tr><td>{_esc(m["topic_es"])}<br/>'
            f'<span style="font-size:8pt;color:#666">{_esc(m["topic_en"])}</span></td>'
            f'<td>{" · ".join(refs)}</td></tr>'
        )
    body = "".join(rows)
    return f"""<h2>Mapeo cruzado / Cross-framework mapping</h2>
<p>Un mismo requisito de seguridad expresado en distintos vocabularios
regulatorios. Facilita defender un hallazgo ante múltiples auditores
al mismo tiempo.</p>
<div class="bilingual-block">
  <span class="en-label">EN</span>
  The same security requirement as expressed under different regulatory
  vocabularies. Useful when defending a finding to multiple auditors
  simultaneously.
</div>
<table class="summary-table">
<thead><tr>
  <th style="width:30%">Tema / Topic</th>
  <th>Referencias cruzadas / Cross-references</th>
</tr></thead>
<tbody>{body}</tbody>
</table>"""


def _framework_section(fw_id: str, results: list[dict], narratives: dict[str, dict]) -> str:
    meta = FRAMEWORK_META.get(fw_id, {"title_es": fw_id, "scope_es": ""})
    counts = _aggregate_counts(results)
    risk_label, risk_color = _risk_level(counts)
    cards = "\n".join(
        _finding_card(r, narratives.get(r.get("control_id", "")))
        for r in _sort_results(results)
    )
    return f"""<h2>{_esc(meta["title_es"])}</h2>
<p style="margin-top:0">
<strong>Alcance:</strong> {_esc(meta.get("scope_es", ""))} ·
<strong>Controles ejecutados:</strong> {len(results)} ·
<strong style="color:{_VERDICT_COLOR["FAIL"]}">FAIL: {counts["FAIL"]}</strong> ·
PASS: {counts["PASS"]} ·
Riesgo: <span style="color:{risk_color};font-weight:700">{risk_label}</span>
</p>
{_summary_table(results)}
{cards}
"""


def render_multi_framework_html(
    framework_results: dict[str, list[dict]],
    *,
    host: str,
    client_name: str = "",
    narratives: dict[str, dict] | None = None,
    audit_date: datetime | None = None,
    repro_hash: str | None = None,
) -> str:
    """Render a consolidated multi-framework compliance audit HTML.

    framework_results: {framework_id: [CheckResult-like dict, ...]}
    host: audited host or scope label (e.g. "atm-001.bank.local")
    client_name: banking client name for cover
    narratives: optional LLM prose keyed by control_id (shared across frameworks)
    repro_hash: override hash; auto-computed if not supplied.
    """
    if not framework_results:
        raise ValueError("framework_results must contain at least one framework")

    audit_date = audit_date or datetime.now()
    narratives = narratives or {}
    repro_hash = repro_hash or compute_repro_hash(framework_results)

    all_results: list[dict] = [r for lst in framework_results.values() for r in lst]
    totals = _aggregate_counts(all_results)
    total_checks = len(all_results)
    total_crit = sum(_critical_fail_count(lst) for lst in framework_results.values())
    overall_risk_label, overall_risk_color = _risk_level(totals)

    frameworks_seen = set(framework_results)
    cross_map_html = _cross_mapping_section(frameworks_seen)
    summary_html = _cross_framework_summary_table(framework_results)

    per_fw_sections = "\n".join(
        _framework_section(fw_id, framework_results[fw_id], narratives)
        for fw_id in sorted(framework_results)
    )

    per_fw_appendices = "\n".join(
        f'<h3>{_esc(FRAMEWORK_META.get(fw_id, {}).get("title_es", fw_id))}</h3>\n'
        + "\n".join(_appendix_evidence(r) for r in _sort_results(framework_results[fw_id]))
        for fw_id in sorted(framework_results)
    )

    css = _css().replace("var(--hash)", f'"{repro_hash[:16]}..."')
    client_line = (
        f"Cliente: <strong>{_esc(client_name)}</strong> · "
        if client_name else ""
    )

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Auditoría Consolidada — {_esc(host)} — {audit_date.strftime('%Y-%m-%d')}</title>
<style>{css}
.risk-banner {{
  display:inline-block; padding:4pt 10pt; border-radius:4pt;
  color:#fff; font-weight:700; font-size:10pt; background:{overall_risk_color};
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

<h1>Auditoría de cumplimiento consolidada</h1>
<div class="cover-meta">
  {client_line}Host: <strong>{_esc(host)}</strong> ·
  Fecha / Date: {audit_date.strftime('%Y-%m-%d %H:%M')} ·
  Frameworks: <strong>{len(framework_results)}</strong>
</div>
<div class="cover-meta">
  Riesgo agregado / Overall risk:
  <span class="risk-banner">{overall_risk_label}</span>
</div>
<div class="repro-hash">Hash reproducibilidad / Reproducibility hash: {_esc(repro_hash)}</div>

<h2>Resumen ejecutivo consolidado</h2>
<p>Se ejecutaron <strong>{total_checks}</strong> controles a través de
<strong>{len(framework_results)}</strong> frameworks de cumplimiento.
Resultados agregados:
<strong style="color:{_VERDICT_COLOR['FAIL']}">{totals['FAIL']} FAIL</strong>
(incluidos <strong style="color:#c1272d">{total_crit} críticos</strong>),
<strong style="color:{_VERDICT_COLOR['PASS']}">{totals['PASS']} PASS</strong>,
{totals['N/A']} N/A, {totals['ERROR']} ERROR.
Nivel de riesgo agregado:
<strong style="color:{overall_risk_color}">{overall_risk_label}</strong>.</p>

<div class="bilingual-block">
  <span class="en-label">EN</span>
  <strong>Executive summary (consolidated).</strong>
  {total_checks} controls were executed across {len(framework_results)}
  compliance frameworks. Aggregate results:
  <strong style="color:{_VERDICT_COLOR['FAIL']}">{totals['FAIL']} FAIL</strong>
  (including <strong style="color:#c1272d">{total_crit} critical</strong>),
  <strong style="color:{_VERDICT_COLOR['PASS']}">{totals['PASS']} PASS</strong>,
  {totals['N/A']} N/A, {totals['ERROR']} ERROR.
  Overall risk:
  <strong style="color:{overall_risk_color}">{overall_risk_label}</strong>.
</div>

<h2>Desglose por framework / Per-framework breakdown</h2>
{summary_html}

{cross_map_html}

<h2>Detalle por framework / Framework detail sections</h2>
{per_fw_sections}

<div class="appendix">
<h2>Apéndice A — Evidencia cruda por framework / Appendix A — Raw evidence per framework</h2>
<p>Comandos ejecutados y output stdout/stderr sin procesar, agrupados por
framework. Permite reproducir manualmente cada hallazgo.</p>
{per_fw_appendices}
</div>

<div class="footer-note">
Este reporte consolidado es válido únicamente acompañado del artifact JSON cuyo
SHA-256 coincide con <code>{_esc(repro_hash[:32])}...</code>. Cualquier modificación
del JSON invalida este reporte. Generado por Kryon compliance engine.
<br/>
This consolidated report is valid only alongside the JSON artifact whose SHA-256
matches the hash above. Any modification to the JSON invalidates this report.
</div>

</body></html>
"""


def render_multi_framework_pdf(
    framework_results: dict[str, list[dict]],
    output_path: str,
    **kwargs: Any,
) -> str:
    """Render consolidated HTML and convert to PDF via weasyprint.

    Returns the output path. Raises ImportError if weasyprint is missing.
    """
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "weasyprint is required for PDF output; install with `pip install weasyprint`"
        ) from exc

    html_str = render_multi_framework_html(framework_results, **kwargs)
    HTML(string=html_str).write_pdf(output_path)
    return output_path


__all__ = [
    "CROSS_MAPPINGS",
    "FRAMEWORK_META",
    "compute_repro_hash",
    "render_multi_framework_html",
    "render_multi_framework_pdf",
]
