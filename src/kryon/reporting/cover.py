"""F85.H — Cover page + signature block renderer.

The legacy report stack drops you into the executive summary on
page 1 with no branding context: no client logo, no classification
banner, no audit identification. For a deliverable to a bank that
should never happen.

This module produces two pieces of HTML that the generator splices
into every report:

  * ``render_cover_page`` — full first-page block: client logo +
    kryon logo, engagement title, scope, date, version, classification
    banner. CSS is self-contained so weasyprint renders it page-1.

  * ``render_signature_block`` — last-page block: auditor name,
    engagement ID, reproducibility hash, signature line. Closes the
    PDF with the artefacts a regulated client needs to file.

Both pieces honour the ``BrandingConfig`` (logo URL, color, footer
text) and the new ``ReportConfig`` branding fields (client_logo_path,
client_color, classification, auditor, engagement_id,
reproducibility_hash).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _file_to_data_uri(path: str | Path | None) -> str:
    """Convert a local image path to a base64 data URI so weasyprint
    can embed it without a network fetch. Returns empty string for
    None / missing / non-image.

    HTTP(S) URLs and existing data: URIs pass through untouched.
    """
    if not path:
        return ""
    src = str(path)
    if src.startswith(("http://", "https://", "data:")):
        return src
    p = Path(src)
    if not p.exists() or not p.is_file():
        return ""
    suffix = p.suffix.lower().lstrip(".")
    mime_map = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "svg": "image/svg+xml",
        "webp": "image/webp",
        "gif": "image/gif",
    }
    mime = mime_map.get(suffix, "application/octet-stream")
    try:
        import base64

        b = p.read_bytes()
        return f"data:{mime};base64,{base64.b64encode(b).decode('ascii')}"
    except OSError:
        return ""


_VALID_CLASSIFICATIONS = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")


def _normalise_classification(value: str) -> str:
    v = (value or "INTERNAL").strip().upper()
    if v not in _VALID_CLASSIFICATIONS:
        return "INTERNAL"
    return v


def _classification_color(classification: str) -> str:
    """Bank-standard color coding for the classification banner."""
    return {
        "PUBLIC": "#2e7d32",  # green
        "INTERNAL": "#1565c0",  # blue
        "CONFIDENTIAL": "#ef6c00",  # orange
        "RESTRICTED": "#c62828",  # red
    }.get(classification, "#1565c0")


def render_cover_page(
    *,
    title: str,
    client_name: str,
    client_logo_path: str | None = None,
    kryon_logo_uri: str = "",
    target_scope: str = "",
    engagement_id: str = "",
    classification: str = "INTERNAL",
    date: str = "",
    auditor: str = "",
    accent_color: str = "#0070d2",
) -> str:
    """Build the page-1 cover HTML block.

    No external CSS — everything is inlined so weasyprint renders it
    page-1 even if the template's stylesheet failed to load.
    """
    from kryon.reporting.firm import (
        FIRM_ACCENT,
        FIRM_AUDITOR,
        FIRM_NAME,
        FIRM_NAVY_BOTTOM,
        FIRM_NAVY_TOP,
        FIRM_TAGLINE,
        firm_logo_data_uri,
    )

    firm_logo = firm_logo_data_uri()
    cls = _normalise_classification(classification)
    cls_es = {"PUBLIC": "PÚBLICO", "INTERNAL": "INTERNO", "CONFIDENTIAL": "CONFIDENCIAL", "RESTRICTED": "RESTRINGIDO"}.get(cls, cls)
    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    accent = accent_color or FIRM_ACCENT
    auditor = auditor or FIRM_AUDITOR

    logo_html = (
        f'<img src="{firm_logo}" alt="{FIRM_NAME}" class="kr-firm-logo">'
        if firm_logo
        else f'<div class="kr-firm-name">{FIRM_NAME}</div>'
    )

    return f"""<style>
/* The cover is page 1; base.html's `@page :first {{ margin: 0 }}` makes it bleed full-page.
   (weasyprint ignores named @page here, but honours :first with the body margin reset.) */
.kr-cover {{
    page-break-after: always; height: 297mm; width: 210mm; padding: 24mm 22mm;
    box-sizing: border-box; font-family: 'DejaVu Sans', 'Liberation Sans', sans-serif;
    color: #eaf1fb; position: relative; overflow: hidden;
    background: linear-gradient(160deg, {FIRM_NAVY_TOP} 0%, {FIRM_NAVY_BOTTOM} 100%);
}}
.kr-rings {{ position: absolute; right: -120mm; top: 70mm; width: 220mm; height: 220mm; opacity: 0.5; }}
.kr-conf {{
    position: absolute; top: 18mm; right: 22mm; border: 1px solid rgba(255,255,255,0.45);
    color: #cfe0f5; border-radius: 14px; padding: 5px 14px; font-size: 9px; font-weight: 700; letter-spacing: 2px;
}}
.kr-firm {{ margin-top: 6mm; }}
.kr-firm-logo {{ height: 38mm; width: auto; }}
.kr-firm-name {{ font-size: 30px; font-weight: 700; letter-spacing: 4px; color: #ffffff; }}
.kr-firm-wordmark {{ font-size: 26px; font-weight: 700; letter-spacing: 6px; color: #ffffff; margin-top: 4px; }}
.kr-firm-tagline {{ font-size: 11px; letter-spacing: 3px; color: {accent}; font-weight: 700; margin-top: 6px; }}
.kr-cover-kicker {{ margin-top: 40mm; font-size: 12px; letter-spacing: 4px; color: {accent}; font-weight: 700; }}
.kr-cover-title {{ margin-top: 10px; font-size: 38px; font-weight: 700; color: #ffffff; line-height: 1.15; }}
.kr-cover-subtitle {{ margin-top: 12px; font-size: 15px; color: #9fb6d4; max-width: 130mm; }}
.kr-accent-line {{ width: 22mm; height: 3px; background: {accent}; margin-top: 16px; }}
.kr-cover-meta {{
    position: absolute; bottom: 30mm; left: 22mm; right: 22mm;
    border-top: 1px solid rgba(255,255,255,0.18); padding-top: 16px;
    display: grid; grid-template-columns: 1fr 1fr; gap: 14px 24px; font-size: 13px; color: #eaf1fb;
}}
.kr-cover-meta strong {{
    display: block; color: {accent}; font-size: 10px; text-transform: uppercase;
    letter-spacing: 1px; margin-bottom: 3px;
}}
.kr-cover-footer-text {{
    position: absolute; bottom: 14mm; left: 22mm; right: 22mm; text-align: center;
    font-size: 9px; color: #7e93b3;
}}
</style>
<div class="kr-cover">
    <svg class="kr-rings" viewBox="0 0 400 400" xmlns="http://www.w3.org/2000/svg">
        <g fill="none" stroke="{accent}" stroke-width="1" opacity="0.35">
            <circle cx="200" cy="200" r="80"/><circle cx="200" cy="200" r="130"/>
            <circle cx="200" cy="200" r="180"/><circle cx="200" cy="200" r="60" opacity="0.6"/>
        </g>
    </svg>
    <div class="kr-conf">DOCUMENTO {cls_es}</div>
    <div class="kr-firm">
        {logo_html}
        <div class="kr-firm-tagline">{FIRM_TAGLINE}</div>
    </div>
    <div class="kr-cover-kicker">AUDITORÍA TÉCNICA</div>
    <div class="kr-cover-title">{title}</div>
    <div class="kr-cover-subtitle">Evaluación de seguridad · {target_scope or client_name or ""}</div>
    <div class="kr-accent-line"></div>
    <div class="kr-cover-meta">
        <div><strong>Cliente</strong>{client_name or "—"}</div>
        <div><strong>Alcance</strong>{target_scope or "—"}</div>
        <div><strong>Preparado por</strong>{auditor}</div>
        <div><strong>Fecha</strong>{date}</div>
        <div><strong>Engagement ID</strong>{engagement_id or "—"}</div>
        <div><strong>Clasificación</strong>{cls_es}</div>
    </div>
    <div class="kr-cover-footer-text">
        Este documento contiene informaci&oacute;n {cls_es.lower()}.
        Distribuci&oacute;n restringida a destinatarios autorizados. &copy; {FIRM_NAME}.
    </div>
</div>"""


def render_signature_block(
    *,
    auditor: str = "",
    engagement_id: str = "",
    reproducibility_hash: str = "",
    date: str = "",
    accent_color: str = "#0070d2",
) -> str:
    """Final-page signature + reproducibility block."""
    from kryon.reporting.firm import FIRM_ACCENT, FIRM_AUDITOR

    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    accent = accent_color or FIRM_ACCENT
    auditor = auditor or FIRM_AUDITOR

    hash_row = ""
    if reproducibility_hash:
        hash_row = (
            f"<div><strong>Hash de reproducibilidad</strong>"
            f'<code class="kr-sig-hash">{reproducibility_hash}</code></div>'
        )

    return f"""<style>
.kr-signature {{
    page-break-before: always;
    padding: 30mm 25mm;
    font-family: 'DejaVu Sans', 'Liberation Sans', sans-serif;
    color: #222;
}}
.kr-signature h2 {{
    color: {accent};
    border-bottom: 2px solid {accent};
    padding-bottom: 6px;
}}
.kr-signature-grid {{
    margin-top: 16px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    font-size: 13px;
}}
.kr-signature-grid strong {{
    display: block;
    color: #888;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 2px;
}}
.kr-sig-hash {{
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 11px;
    color: #444;
    word-break: break-all;
}}
.kr-sig-line {{
    margin-top: 30mm;
    border-top: 1px solid #999;
    padding-top: 4px;
    width: 60%;
    font-size: 11px;
    color: #888;
}}
.kr-sig-disclaimer {{
    margin-top: 12mm;
    font-size: 10px;
    color: #777;
    line-height: 1.5;
}}
</style>
<div class="kr-signature">
    <h2>Atestaci&oacute;n y reproducibilidad</h2>
    <div class="kr-signature-grid">
        <div><strong>Auditor</strong>{auditor}</div>
        <div><strong>Engagement ID</strong>{engagement_id or "—"}</div>
        <div><strong>Fecha de emisi&oacute;n</strong>{date}</div>
        <div><strong>Generado por</strong>Kryon v2.1.0 (autom&aacute;tico)</div>
        {hash_row}
    </div>
    <div class="kr-sig-line">Firma del auditor responsable</div>
    <p class="kr-sig-disclaimer">
        Este informe documenta hallazgos detectados al momento de la
        evaluaci&oacute;n. Los controles compensatorios y remediaciones
        descritas son recomendaciones; la ejecuci&oacute;n y verificaci&oacute;n
        posterior son responsabilidad del cliente. El hash de reproducibilidad
        permite verificar que las decisiones algor&iacute;tmicas sobre los
        hallazgos deterministas no cambiaron entre ejecuciones del runner.
    </p>
</div>"""
