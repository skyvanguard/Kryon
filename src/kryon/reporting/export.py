"""Export utilities — save reports to file system."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

_REPORTS_DIR = Path.home() / ".kryon" / "reports"


def save_report(html: str, client_name: str = "", report_type: str = "technical") -> Path:
    """Save HTML report to filesystem. Returns the file path."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = client_name.lower().replace(" ", "_")[:30] if client_name else "report"
    filename = f"{slug}_{report_type}_{ts}.html"
    path = _REPORTS_DIR / filename
    path.write_text(html, encoding="utf-8")
    return path


def save_pdf(pdf_bytes: bytes, client_name: str = "", report_type: str = "technical") -> Path:
    """Save PDF report to filesystem. Returns the file path."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = client_name.lower().replace(" ", "_")[:30] if client_name else "report"
    filename = f"{slug}_{report_type}_{ts}.pdf"
    path = _REPORTS_DIR / filename
    path.write_bytes(pdf_bytes)
    return path


def list_reports() -> list[dict]:
    """List all generated reports."""
    if not _REPORTS_DIR.exists():
        return []

    reports = []
    for f in sorted(_REPORTS_DIR.iterdir(), reverse=True):
        if f.suffix in (".html", ".pdf"):
            reports.append(
                {
                    "filename": f.name,
                    "path": str(f),
                    "format": f.suffix[1:],
                    "size_kb": round(f.stat().st_size / 1024, 1),
                    "created": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
                }
            )
    return reports


def get_report_path(filename: str) -> Path | None:
    """Get full path for a report by filename."""
    path = _REPORTS_DIR / filename
    return path if path.exists() else None
