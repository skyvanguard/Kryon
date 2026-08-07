"""Report generator — orchestrates all sections into a final HTML/PDF report."""

from __future__ import annotations

import logging
from pathlib import Path

from kryon.intelligence.mitre import MITREMapper
from kryon.intelligence.models import Finding
from kryon.reporting.branding import BrandingConfig, apply_branding
from kryon.reporting.cover import render_cover_page, render_signature_block
from kryon.reporting.models import ReportConfig, ReportType
from kryon.reporting.sections.asset_inventory import render_asset_inventory
from kryon.reporting.sections.attack_paths import render_attack_path_summary
from kryon.reporting.sections.compliance import render_compliance_mapping
from kryon.reporting.sections.executive_summary import render_executive_summary
from kryon.reporting.sections.findings_table import render_findings_table
from kryon.reporting.sections.mitre_coverage import render_mitre_heatmap
from kryon.reporting.sections.risk_overview import render_risk_overview
from kryon.reporting.sections.scope_methodology import render_scope_methodology
from kryon.reporting.sections.trend_analysis import render_trend_analysis

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Orchestrates report generation from findings."""

    def __init__(self, intelligence: MITREMapper | None = None):
        self.mitre = intelligence or MITREMapper()

    async def generate(self, findings: list[Finding], config: ReportConfig) -> str:
        """Generate complete report. Returns HTML string."""
        # Enrich findings with MITRE mappings if not already present
        for f in findings:
            if not f.mitre:
                text = f"{f.title} {f.description}"
                f.mitre = self.mitre.map_finding(text, tool_name=f.tool_source)

        # Build sections based on report type
        sections: list[str] = []

        if config.report_type in (ReportType.EXECUTIVE, ReportType.TECHNICAL):
            sections.append(render_executive_summary(findings, config.client_name, config.target_scope))

        # Scope & methodology — only on technical/compliance reports (executives don't need it).
        if config.report_type in (ReportType.TECHNICAL, ReportType.COMPLIANCE):
            sections.append(render_scope_methodology(findings, config.client_name, config.target_scope, config.date))

        sections.append(render_risk_overview(findings))

        if config.report_type in (ReportType.TECHNICAL, ReportType.COMPLIANCE):
            sections.append(render_findings_table(findings, config.include_evidence))
            # Correlated attack-path chains + finding trend over time. Both render
            # a "no data" note on empty input, so they never break the report.
            sections.append(render_attack_path_summary(findings))
            sections.append(render_trend_analysis(findings))

        if config.include_mitre:
            sections.append(render_mitre_heatmap(findings))

        sections.append(render_asset_inventory(findings))

        # Compliance sections
        for fw in config.include_compliance:
            sections.append(render_compliance_mapping(findings, fw))

        if config.report_type == ReportType.COMPLIANCE and not config.include_compliance:
            sections.append(render_compliance_mapping(findings, "pci_dss"))
            sections.append(render_compliance_mapping(findings, "iso_27001"))

        # Dedicated PCI-DSS report
        if config.report_type == ReportType.PCI_DSS:
            from kryon.reporting.sections.pci_dss_report import render_pci_dss_report

            sections.append(render_pci_dss_report(findings))

        # Dedicated SOC2 report
        if config.report_type == ReportType.SOC2:
            from kryon.reporting.sections.soc2_report import render_soc2_report

            sections.append(render_soc2_report(findings))

        # Report titles
        type_titles = {
            ReportType.EXECUTIVE: "Informe Ejecutivo de Seguridad",
            ReportType.TECHNICAL: "Informe Técnico de Seguridad",
            ReportType.COMPLIANCE: "Informe de Cumplimiento",
            ReportType.PCI_DSS: "Evaluación de Cumplimiento PCI-DSS v4.0",
            ReportType.SOC2: "Evaluación de Cumplimiento SOC 2 Type II",
        }
        title = type_titles.get(config.report_type, "Informe de Seguridad")
        subtitle = f"Análisis {config.report_type.value} de seguridad"

        # F85.H — Cover page + signature block. Both are best-effort:
        # if the client logo / accent color isn't set we render the
        # cover with placeholders so the deliverable still has page-1
        # branding identity instead of dropping straight into the
        # executive summary.
        from kryon.reporting.firm import FIRM_ACCENT as _FIRM_ACCENT

        accent = config.client_color or _FIRM_ACCENT
        cover_html = render_cover_page(
            title=title,
            client_name=config.client_name,
            client_logo_path=config.client_logo_path or config.logo_path,
            target_scope=config.target_scope,
            engagement_id=config.engagement_id,
            classification=config.classification,
            date=config.date,
            auditor=config.auditor,
            accent_color=accent,
        )
        signature_html = render_signature_block(
            auditor=config.auditor,
            engagement_id=config.engagement_id,
            reproducibility_hash=config.reproducibility_hash,
            date=config.date,
            accent_color=accent,
        )

        content = cover_html + "\n" + "\n".join(sections) + "\n" + signature_html

        html = self._render_template(
            title=title,
            subtitle=subtitle,
            client_name=config.client_name,
            target_scope=config.target_scope,
            date=config.date,
            content=content,
        )

        # F85.H — Apply legacy header/footer branding on top (CSS vars,
        # company name banner). The cover page above already lives in
        # the content body so it doesn't conflict; apply_branding's
        # ``<body>`` injection lands after the cover.
        if config.client_color or config.client_logo_path:
            branding = BrandingConfig(
                logo_url=config.client_logo_path or "",
                primary_color=config.client_color or "#00d4ff",
                company_name=config.client_name or "KRYON Security",
                footer_text=f"{config.classification} — Distribución restringida",
            )
            html = apply_branding(html, branding)

        return html

    async def to_pdf(self, html: str) -> bytes:
        """Convert HTML report to PDF using weasyprint.

        F202.X — also catches OSError (Windows missing GTK3 runtime).
        """
        try:
            from weasyprint import HTML

            return HTML(string=html).write_pdf()
        except ImportError:
            raise ImportError("weasyprint is required for PDF generation. Install with: pip install kryon[reporting]")
        except OSError as exc:
            raise RuntimeError(
                f"WeasyPrint native deps missing ({exc}). On Windows install GTK3 runtime: "
                "https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases"
            ) from exc

    def _render_template(self, **kwargs: str) -> str:
        """Render the base HTML template with string.Template (no jinja2 dep)."""
        template_path = _TEMPLATE_DIR / "base.html"
        if template_path.exists():
            raw = template_path.read_text(encoding="utf-8")
            # Simple Jinja2-like replacement using regex
            import re

            result = raw
            for key, value in kwargs.items():
                # Replace {{ key }} patterns. Use a function replacement so `value` is
                # inserted LITERALLY — passing it as the 2nd arg to re.sub treats `\1`,
                # `\g<..>`, or a trailing `\` in the value (LLM-derived evidence/titles)
                # as backreferences → re.error crashing the whole report. re.escape(key)
                # guards against regex metacharacters in the key.
                result = re.sub(r"\{\{\s*" + re.escape(key) + r"\s*\}\}", lambda _m, v=str(value): v, result)
            # Remove unmatched {% %} blocks (conditionals we don't need to evaluate)
            result = re.sub(r"\{%.*?%\}", "", result)
            return result

        # Fallback minimal template
        return f"""<!DOCTYPE html>
<html><head><title>{kwargs.get("title", "Report")}</title></head>
<body>{kwargs.get("content", "")}</body></html>"""
