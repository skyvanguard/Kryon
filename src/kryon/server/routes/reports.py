"""Report generation API endpoints.

ISOLATION TODO (3rd bug-hunt G5): these endpoints are NOT yet cross-client (BOLA)
isolated. Reports are filesystem-only (``~/.kryon/reports/``) and carry no structured
client_id — the filename is a lossy ``_safe_slug(client_name)``, so it can't be mapped
back to a store client_id to guard against. Closing this properly requires persisting
reports in the store WITH a client_id (or a client_name→client_id map). Left explicitly
un-guarded rather than shipping a guess that would break the single-tenant flow.
Under single-tenant API-key mode (the supported deployment) this has no impact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.rbac import require_permission
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

# Reports aren't client-isolated yet (filenames can't be mapped back to a
# client_id — see module docstring; a proper fix needs the store to persist
# client_id per report). Until then, at least require reports:read (not just an
# API key) so the endpoint isn't role-agnostic; the POST additionally needs write.
router = APIRouter(
    tags=["reports"],
    dependencies=[Depends(require_api_key), Depends(require_permission("reports:read"))],
)


class ReportRequest(BaseModel):
    findings_json: str = Field("[]", max_length=10_000_000)
    report_type: Literal["executive", "technical", "compliance"] = "technical"
    format: Literal["html", "pdf"] = "html"
    client_name: str = Field("", max_length=200)
    target_scope: str = Field("", max_length=500)
    include_compliance: list[str] = Field(default=[], max_length=20)


class ReportResponse(BaseModel):
    filename: str
    format: str
    path: str


@router.post("/reports", dependencies=[Depends(require_permission("reports:write"))])
async def generate_report(request: ReportRequest) -> ReportResponse:
    """Generate a security report from findings."""
    from kryon.intelligence.models import Finding
    from kryon.reporting.export import save_pdf, save_report
    from kryon.reporting.generator import ReportGenerator
    from kryon.reporting.models import ReportConfig, ReportType

    try:
        raw = json.loads(request.findings_json)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("Malformed findings_json: %s", e)
        raise HTTPException(status_code=400, detail="Malformed findings_json")
    try:
        findings = [Finding(**f) for f in raw]
    except Exception as e:
        logger.warning("Invalid finding data: %s", e)
        raise HTTPException(status_code=400, detail="Invalid finding data")

    config = ReportConfig(
        report_type=ReportType(request.report_type),
        client_name=request.client_name,
        target_scope=request.target_scope,
        include_compliance=request.include_compliance,
        format=request.format,
    )

    gen = ReportGenerator()
    html = await gen.generate(findings, config)

    if request.format == "pdf":
        try:
            pdf_bytes = await gen.to_pdf(html)
            path = save_pdf(pdf_bytes, request.client_name, request.report_type)
        except ImportError as e:
            logger.warning("PDF generation not available: %s", e)
            raise HTTPException(status_code=501, detail="PDF generation not available")
    else:
        path = save_report(html, request.client_name, request.report_type)

    logger.info(
        "Report generated: type=%s format=%s client=%s", request.report_type, request.format, request.client_name
    )
    return ReportResponse(filename=path.name, format=request.format, path=str(path))


@router.get("/reports")
async def list_reports() -> list[dict]:
    """List all generated reports."""
    from kryon.reporting.export import list_reports

    return list_reports()


@router.get("/reports/{filename}/download")
async def download_report(filename: str) -> FileResponse:
    """Stream a generated report file for download.

    The dashboard fetches this with the API key header and turns the
    response into a browser download. Guarded against path traversal:
    the name must be a bare basename with a known report extension.
    """
    from kryon.reporting.export import get_report_path

    if filename != Path(filename).name or Path(filename).suffix not in (".pdf", ".html"):
        raise HTTPException(status_code=400, detail="Invalid report filename")
    path = get_report_path(filename)
    if path is None:
        raise HTTPException(status_code=404, detail="Report not found")
    media = "application/pdf" if path.suffix == ".pdf" else "text/html"
    return FileResponse(str(path), media_type=media, filename=filename)
