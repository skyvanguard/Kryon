"""Report generator — orchestrates all sections into a final HTML/PDF report."""

from __future__ import annotations

import logging
from pathlib import Path

from kryon.intelligence.mitre import MITREMapper
from kryon.intelligence.models import Finding
from kryon.reporting.models import ReportConfig, ReportType
from kryon.reporting.sections.asset_inventory import render_asset_inventory
from kryon.reporting.sections.compliance import render_compliance_mapping
from kryon.reporting.sections.executive_summary import render_executive_summary
from kryon.reporting.sections.findings_table import render_findings_table
from kryon.reporting.sections.mitre_coverage import render_mitre_heatmap
from kryon.reporting.sections.risk_overview import render_risk_overview

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

        sections.append(render_risk_overview(findings))

        if config.report_type in (ReportType.TECHNICAL, ReportType.COMPLIANCE):
            sections.append(render_findings_table(findings, config.include_evidence))

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

        content = "\n".join(sections)

        # Report titles
        type_titles = {
            ReportType.EXECUTIVE: "Executive Security Assessment",
            ReportType.TECHNICAL: "Technical Security Assessment Report",
            ReportType.COMPLIANCE: "Compliance Assessment Report",
            ReportType.PCI_DSS: "PCI-DSS v4.0 Compliance Assessment",
            ReportType.SOC2: "SOC 2 Type II Compliance Assessment",
        }
        title = type_titles.get(config.report_type, "Security Assessment Report")
        subtitle = f"Comprehensive {config.report_type.value} analysis"

        html = self._render_template(
            title=title,
            subtitle=subtitle,
            client_name=config.client_name,
            target_scope=config.target_scope,
            date=config.date,
            content=content,
        )

        return html

    async def to_pdf(self, html: str) -> bytes:
        """Convert HTML report to PDF using weasyprint."""
        try:
            from weasyprint import HTML

            return HTML(string=html).write_pdf()
        except ImportError:
            raise ImportError("weasyprint is required for PDF generation. Install with: pip install kryon[reporting]")

    def _render_template(self, **kwargs: str) -> str:
        """Render the base HTML template with string.Template (no jinja2 dep)."""
        template_path = _TEMPLATE_DIR / "base.html"
        if template_path.exists():
            raw = template_path.read_text(encoding="utf-8")
            # Simple Jinja2-like replacement using regex
            import re

            result = raw
            for key, value in kwargs.items():
                # Replace {{ key }} patterns
                result = re.sub(r"\{\{\s*" + key + r"\s*\}\}", str(value), result)
            # Remove unmatched {% %} blocks (conditionals we don't need to evaluate)
            result = re.sub(r"\{%.*?%\}", "", result)
            return result

        # Fallback minimal template
        return f"""<!DOCTYPE html>
<html><head><title>{kwargs.get("title", "Report")}</title></head>
<body>{kwargs.get("content", "")}</body></html>"""
