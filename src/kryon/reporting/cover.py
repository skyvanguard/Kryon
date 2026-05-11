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
        "PUBLIC": "#2e7d32",       # green
        "INTERNAL": "#1565c0",     # blue
        "CONFIDENTIAL": "#ef6c00", # orange
        "RESTRICTED": "#c62828",   # red
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
    cls = _normalise_classification(classification)
    cls_color = _classification_color(cls)
    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    client_logo_src = _file_to_data_uri(client_logo_path)
    accent = accent_color or "#0070d2"

    client_logo_html = (
        f'<img src="{client_logo_src}" alt="{client_name or "client"}" '
        f'class="kr-cover-client-logo">'
    ) if client_logo_src else (
        f'<div class="kr-cover-client-placeholder">{client_name or "Cliente"}</div>'
    )
    kryon_logo_html = (
        f'<img src="{kryon_logo_uri}" alt="Kryon" class="kr-cover-kryon-logo">'
        if kryon_logo_uri else ""
    )

    return f"""<style>
@page {{
    size: A4;
    margin: 0;
}}
.kr-cover {{
    page-break-after: always;
    height: 297mm;
    width: 210mm;
    padding: 30mm 25mm;
    box-sizing: border-box;
    font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif;
    color: #222;
    position: relative;
    background: linear-gradient(180deg, #ffffff 0%, #f5f8fb 100%);
}}
.kr-cover-classification {{
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    background: {cls_color};
    color: #fff;
    text-align: center;
    padding: 8px 0;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 2px;
}}
.kr-cover-client-logo,
.kr-cover-client-placeholder {{
    max-width: 280px;
    max-height: 80px;
    margin-bottom: 12px;
    font-size: 28px;
    color: #444;
    font-weight: 600;
}}
.kr-cover-title {{
    margin-top: 70mm;
    font-size: 34px;
    font-weight: 700;
    color: {accent};
    line-height: 1.2;
}}
.kr-cover-subtitle {{
    margin-top: 12px;
    font-size: 18px;
    color: #555;
}}
.kr-cover-meta {{
    margin-top: 60mm;
    border-top: 2px solid {accent};
    padding-top: 16px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    font-size: 13px;
}}
.kr-cover-meta strong {{
    display: block;
    color: #888;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 2px;
}}
.kr-cover-kryon-logo {{
    position: absolute;
    bottom: 25mm;
    right: 25mm;
    max-height: 32px;
    opacity: 0.7;
}}
.kr-cover-footer-text {{
    position: absolute;
    bottom: 12mm;
    left: 25mm;
    right: 25mm;
    text-align: center;
    font-size: 10px;
    color: #999;
}}
</style>
<div class="kr-cover">
    <div class="kr-cover-classification">{cls}</div>
    {client_logo_html}
    <div class="kr-cover-title">{title}</div>
    <div class="kr-cover-subtitle">Auditoría de seguridad técnica</div>
    <div class="kr-cover-meta">
        <div><strong>Cliente</strong>{client_name or "—"}</div>
        <div><strong>Engagement ID</strong>{engagement_id or "—"}</div>
        <div><strong>Alcance</strong>{target_scope or "—"}</div>
        <div><strong>Fecha</strong>{date}</div>
        <div><strong>Auditor</strong>{auditor or "Kryon"}</div>
        <div><strong>Clasificación</strong>{cls}</div>
    </div>
    {kryon_logo_html}
    <div class="kr-cover-footer-text">
        Este documento contiene informaci&oacute;n {cls.lower()}.
        Distribuci&oacute;n restringida a destinatarios autorizados.
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
    if not date:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    accent = accent_color or "#0070d2"

    hash_row = ""
    if reproducibility_hash:
        hash_row = (
            f'<div><strong>Hash de reproducibilidad</strong>'
            f'<code class="kr-sig-hash">{reproducibility_hash}</code></div>'
        )

    return f"""<style>
.kr-signature {{
    page-break-before: always;
    padding: 30mm 25mm;
    font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif;
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
        <div><strong>Auditor</strong>{auditor or "Kryon"}</div>
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
