"""Report generation API endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["reports"], dependencies=[Depends(require_api_key)])


class ReportRequest(BaseModel):
    findings_json: str = "[]"  # JSON array of finding dicts
    report_type: str = "technical"  # executive, technical, compliance
    format: str = "html"  # html, pdf
    client_name: str = ""
    target_scope: str = ""
    include_compliance: list[str] = []


class ReportResponse(BaseModel):
    filename: str
    format: str
    path: str


@router.post("/reports")
async def generate_report(request: ReportRequest) -> ReportResponse:
    """Generate a security report from findings."""
    from kryon.intelligence.models import Finding
    from kryon.reporting.export import save_pdf, save_report
    from kryon.reporting.generator import ReportGenerator
    from kryon.reporting.models import ReportConfig, ReportType

    try:
        raw = json.loads(request.findings_json)
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Malformed findings_json: {e}")
    try:
        findings = [Finding(**f) for f in raw]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid finding data: {e}")

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
            raise HTTPException(status_code=501, detail=str(e))
    else:
        path = save_report(html, request.client_name, request.report_type)

    logger.info("Report generated: type=%s format=%s client=%s", request.report_type, request.format, request.client_name)
    return ReportResponse(filename=path.name, format=request.format, path=str(path))


@router.get("/reports")
async def list_reports() -> list[dict]:
    """List all generated reports."""
    from kryon.reporting.export import list_reports

    return list_reports()
