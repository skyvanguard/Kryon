"""Generate an executive one-pager PDF for ASOBAN / banking prospects (F47).

Reads the live inventory of compliance frameworks from the repo, picks
a profile (A/B/C based on bank size + scope), and produces a single-
page Spanish-language PDF tailored to one prospect.

Usage:
    python scripts/sales/generate_asoban_onepager.py \\
        --cliente "Banco Ejemplo S.A." \\
        --perfil B \\
        --output reports/asoban-onepager-banco-ejemplo.pdf

Perfil:
    A = banco pequeño (< USD 100M, sin ATMs) — PY + CIS OS + PCI
    B = banco mediano (100M-1B, con ATMs)   — A + ATM + Docker + core
    C = banco grande (1B+, SWIFT)           — B + SWIFT
"""

from __future__ import annotations

import argparse
import html
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from kryon.compliance.cis import (  # noqa: E402
    available_frameworks,
    load_framework,
)


PERFILES: dict[str, dict[str, object]] = {
    "A": {
        "label_es": "Perfil A — Banco pequeño",
        "descripcion": "Activos < USD 100M, sin red de cajeros",
        "frameworks": [
            "bcp-py-res-12-2021",
            "cis-ubuntu-22.04-l1",
            "cis-debian-12-l1",
            "cis-rhel-9-l1",
            "pci-dss-4.0",
        ],
        "semanas_recomendadas": "3-4",
    },
    "B": {
        "label_es": "Perfil B — Banco mediano",
        "descripcion": "Activos USD 100M-1B, con red de cajeros",
        "frameworks": [
            "bcp-py-res-12-2021",
            "cis-ubuntu-22.04-l1",
            "cis-debian-12-l1",
            "cis-rhel-9-l1",
            "cis-docker-1.6",
            "pci-dss-4.0",
            "core-banking-hardening",
            "atm-security-bcp-2024",
        ],
        "semanas_recomendadas": "5-6",
    },
    "C": {
        "label_es": "Perfil C — Banco grande",
        "descripcion": "Activos > USD 1B, miembro SWIFT",
        "frameworks": [
            "bcp-py-res-12-2021",
            "cis-ubuntu-22.04-l1",
            "cis-debian-12-l1",
            "cis-rhel-9-l1",
            "cis-docker-1.6",
            "pci-dss-4.0",
            "swift-csp-2024",
            "core-banking-hardening",
            "atm-security-bcp-2024",
        ],
        "semanas_recomendadas": "8-10",
    },
}


_TITLE_ES = {
    "pci-dss-4.0": "PCI-DSS v4.0.1",
    "swift-csp-2024": "SWIFT CSP v2024",
    "bcp-py-res-12-2021": "BCP PY Res. 12/2021",
    "cis-ubuntu-22.04-l1": "CIS Ubuntu 22.04 L1",
    "cis-debian-12-l1": "CIS Debian 12 L1",
    "cis-rhel-9-l1": "CIS RHEL 9 L1",
    "cis-docker-1.6": "CIS Docker 1.6",
    "core-banking-hardening": "Core Banking (T24/Finacle/Flexcube)",
    "atm-security-bcp-2024": "ATM Security BCP PY 2024",
}


def _esc(s: str) -> str:
    return html.escape(str(s))


def build_coverage_rows(selected_ids: list[str]) -> tuple[str, int, int]:
    """Return HTML rows for the coverage table + totals."""
    inv = {}
    for p in available_frameworks():
        fw = load_framework(p)
        inv[fw.metadata.id] = fw

    rows = []
    total_checks = 0
    total_critical = 0
    for fid in selected_ids:
        fw = inv.get(fid)
        if not fw:
            continue
        crit = sum(1 for c in fw.checks if c.severity == "CRITICAL")
        title = _TITLE_ES.get(fid, fid)
        rows.append(
            f"<tr><td>{_esc(title)}</td>"
            f"<td style='text-align:right'>{len(fw.checks)}</td>"
            f"<td style='text-align:right;color:#c1272d;font-weight:700'>{crit}</td></tr>"
        )
        total_checks += len(fw.checks)
        total_critical += crit
    rows.append(
        f"<tr style='border-top:2pt solid #222;font-weight:700'>"
        f"<td>TOTAL</td>"
        f"<td style='text-align:right'>{total_checks}</td>"
        f"<td style='text-align:right;color:#c1272d'>{total_critical}</td></tr>"
    )
    return "\n".join(rows), total_checks, total_critical


def render_html(
    cliente: str,
    perfil_key: str,
    fecha: date,
) -> str:
    perfil = PERFILES[perfil_key]
    rows, total_checks, total_crit = build_coverage_rows(perfil["frameworks"])

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Kryon — Propuesta {_esc(cliente)}</title>
<style>
@page {{
  size: A4;
  margin: 12mm 14mm 14mm 14mm;
  @bottom-center {{
    content: "Confidencial — sólo para uso interno de {_esc(cliente)}";
    font-size: 7.5pt; color: #999;
  }}
}}
body {{ font-family: "Helvetica Neue", Arial, sans-serif; color: #222; font-size: 9.5pt; line-height: 1.35; }}
h1 {{ font-size: 18pt; margin: 0 0 2pt 0; color: #1a1a1a; }}
h2 {{ font-size: 12pt; margin: 10pt 0 4pt 0; color: #2a5d8f; border-bottom: 1px solid #ccc; padding-bottom: 1pt; }}
.header {{ display: flex; justify-content: space-between; align-items: baseline; }}
.subtitle {{ color: #666; font-size: 10pt; margin-top: 2pt; }}
.two-col {{ display: flex; gap: 14pt; margin-top: 6pt; }}
.col {{ flex: 1; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 4pt; font-size: 9pt; }}
th, td {{ border: 1px solid #ddd; padding: 3pt 6pt; text-align: left; }}
th {{ background: #f2f2f2; font-weight: 600; }}
.value-prop {{ background: #f7f7f0; border-left: 3pt solid #2a5d8f; padding: 6pt 10pt; font-size: 9pt; margin: 4pt 0; }}
.stat {{ display: inline-block; margin: 2pt 8pt 2pt 0; }}
.stat .n {{ font-size: 16pt; font-weight: 700; color: #2a5d8f; }}
.stat .lbl {{ font-size: 7.5pt; color: #666; text-transform: uppercase; letter-spacing: 0.4pt; }}
.signature {{ margin-top: 14pt; font-size: 9pt; color: #555; }}
.cta {{ background: #2a5d8f; color: #fff; padding: 4pt 10pt; border-radius: 3pt; display: inline-block; font-weight: 600; font-size: 9.5pt; }}
</style>
</head><body>

<div class="header">
  <div>
    <h1>Kryon · Auditoría de Ciberseguridad Bancaria</h1>
    <div class="subtitle">Propuesta para <strong>{_esc(cliente)}</strong>
        · {fecha.strftime('%Y-%m-%d')}</div>
  </div>
  <div>
    <span class="stat"><span class="n">{total_checks}</span><br/>
      <span class="lbl">Controles</span></span>
    <span class="stat"><span class="n">{total_crit}</span><br/>
      <span class="lbl">Críticos</span></span>
    <span class="stat"><span class="n">{len(perfil["frameworks"])}</span><br/>
      <span class="lbl">Frameworks</span></span>
  </div>
</div>

<h2>Propuesta de valor</h2>
<div class="value-prop">
Kryon ejecuta <strong>{total_checks} controles deterministas</strong>
sobre la infraestructura de {_esc(cliente)}, genera evidencia
reproducible con hash SHA-256 y produce reportes bilingües (ES/EN)
directamente defendibles ante BCP, SIB, auditor externo PCI y
auditoría interna. El modelo LLM corre <strong>100% local</strong>:
ningún dato del banco sale de su infraestructura.
</div>

<div class="two-col">
  <div class="col">
    <h2>Alcance — {_esc(perfil["label_es"])}</h2>
    <p style="margin:2pt 0">{_esc(perfil["descripcion"])}</p>
    <table>
      <thead><tr>
        <th>Marco regulatorio</th>
        <th style="text-align:right">#</th>
        <th style="text-align:right">CRIT</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <p style="font-size:8.5pt;color:#666;margin-top:3pt">
      Duración estimada del engagement:
      <strong>{perfil["semanas_recomendadas"]} semanas</strong>.</p>
  </div>
  <div class="col">
    <h2>Diferenciadores</h2>
    <ul style="margin:4pt 0 4pt 16pt; padding:0;">
      <li>Frameworks <strong>específicos del regulador paraguayo</strong>
          (BCP 12/2021 + disposición ATM 2024)</li>
      <li>Controles nativos para core bancario
          <strong>T24 / Finacle / Flexcube</strong></li>
      <li>Evidencia con hash SHA-256 — reproducible a los 18 meses</li>
      <li>Reporte bilingüe español / inglés en un mismo PDF</li>
      <li>Mapeo cruzado: un hallazgo → PCI-DSS + BCP + SWIFT</li>
      <li>Modelo LLM <strong>local</strong> — cero datos a la nube</li>
      <li>Regresión semanal por CI — no se pierde cobertura entre versiones</li>
    </ul>

    <h2>Próximos pasos</h2>
    <ol style="margin:4pt 0 4pt 16pt; padding:0;">
      <li>Llamada de descubrimiento (30 min, sin compromiso)</li>
      <li>Firma de NDA (plantilla disponible)</li>
      <li>Cuestionario de alcance técnico</li>
      <li>SOW con plazos y precio cerrado</li>
      <li>Kick-off</li>
    </ol>

    <div class="signature">
      <span class="cta">Contacto: ventas@kryon-security.com</span>
    </div>
  </div>
</div>

</body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate ASOBAN one-pager")
    parser.add_argument("--cliente", required=True, help="Nombre del banco prospecto")
    parser.add_argument(
        "--perfil",
        choices=["A", "B", "C"],
        default="B",
        help="Perfil del banco (default: B)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO / "reports" / "asoban-onepager.pdf",
        help="Ruta del PDF de salida",
    )
    parser.add_argument(
        "--html-only",
        action="store_true",
        help="Emitir HTML en lugar de PDF (sin dependencia weasyprint)",
    )
    args = parser.parse_args()

    html_str = render_html(args.cliente, args.perfil, date.today())

    if args.html_only:
        out = args.output.with_suffix(".html")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html_str, encoding="utf-8")
        print(f"HTML escrito: {out}")
        return 0

    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        out = args.output.with_suffix(".html")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html_str, encoding="utf-8")
        print(
            f"weasyprint no instalado; emitido HTML en su lugar: {out}",
            file=sys.stderr,
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_str).write_pdf(str(args.output))
    print(f"PDF escrito: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
