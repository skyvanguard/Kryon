"""Report branding — logo, colors, company name injection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BrandingConfig:
    logo_url: str = ""
    primary_color: str = "#00d4ff"
    company_name: str = "KRYON Security"
    footer_text: str = "Confidential — For authorized recipients only"


def apply_branding(html: str, branding: BrandingConfig) -> str:
    """Inject branding CSS variables and logo into HTML report."""
    css_vars = f"""<style>
:root {{
    --brand-primary: {branding.primary_color};
    --brand-logo: url('{branding.logo_url}');
}}
body {{ font-family: 'Inter', 'Segoe UI', sans-serif; }}
.brand-header {{ border-bottom: 3px solid {branding.primary_color}; padding: 20px; margin-bottom: 30px; }}
.brand-logo {{ max-height: 60px; margin-bottom: 10px; }}
.brand-name {{ color: {branding.primary_color}; font-size: 24px; font-weight: bold; }}
.brand-footer {{ border-top: 1px solid #ccc; padding: 15px; margin-top: 40px; font-size: 11px; color: #666; text-align: center; }}
</style>"""

    logo_html = ""
    if branding.logo_url:
        logo_html = f'<img src="{branding.logo_url}" class="brand-logo" alt="{branding.company_name}">'

    header = f"""<div class="brand-header">
{logo_html}
<div class="brand-name">{branding.company_name}</div>
</div>"""

    footer = f"""<div class="brand-footer">{branding.footer_text}</div>"""

    # Inject after <body> tag
    if "<body" in html:
        html = html.replace("<body>", f"<body>{css_vars}{header}", 1)
        # Handle body with attributes
        import re
        if "<body>" not in html:
            html = re.sub(r"(<body[^>]*>)", rf"\1{css_vars}{header}", html, count=1)
    else:
        html = f"{css_vars}{header}{html}"

    # Inject footer before </body>
    if "</body>" in html:
        html = html.replace("</body>", f"{footer}</body>", 1)
    else:
        html = f"{html}{footer}"

    return html
