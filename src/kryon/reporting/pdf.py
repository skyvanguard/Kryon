"""PDF conversion utilities (requires weasyprint optional dependency)."""

from __future__ import annotations


async def html_to_pdf(html: str) -> bytes:
    """Convert HTML string to PDF bytes.

    F202.X — also catches OSError thrown by WeasyPrint when GTK3 runtime
    DLLs are missing on Windows (libgobject-2.0-0, pango, cairo).
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
