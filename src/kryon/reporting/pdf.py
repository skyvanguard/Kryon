"""PDF conversion utilities (requires weasyprint optional dependency)."""

from __future__ import annotations


async def html_to_pdf(html: str) -> bytes:
    """Convert HTML string to PDF bytes."""
    try:
        from weasyprint import HTML

        return HTML(string=html).write_pdf()
    except ImportError:
        raise ImportError("weasyprint is required for PDF generation. Install with: pip install kryon[reporting]")
