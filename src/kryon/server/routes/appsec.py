"""AppSec API routes — SAST, DAST, SBOM scanning endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger
from kryon.server.models import DASTScanRequest, SASTScanRequest, SBOMRequest
from kryon.tools.common._url_validation import validate_external_url

logger = get_logger(__name__)

router = APIRouter(tags=["appsec"], dependencies=[Depends(require_api_key)])


@router.post("/appsec/sast")
async def run_sast_scan(body: SASTScanRequest) -> dict:
    """Run a SAST scan using Semgrep."""
    from kryon.tools.appsec.semgrep import semgrep_scan

    result = await semgrep_scan.on_invoke_tool(None, body.model_dump_json())
    scan_id = uuid.uuid4().hex[:12]
    logger.info("SAST scan completed: id=%s", scan_id)
    return {"scan_id": scan_id, "tool": "semgrep", "result": result}


@router.post("/appsec/dast")
async def run_dast_scan(body: DASTScanRequest) -> dict:
    """Run a DAST scan using ZAP."""
    url_err = validate_external_url(body.target_url)
    if url_err:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {url_err}")

    from kryon.tools.appsec.zap import zap_baseline_scan

    result = await zap_baseline_scan.on_invoke_tool(None, body.model_dump_json())
    scan_id = uuid.uuid4().hex[:12]
    logger.info("DAST scan completed: id=%s", scan_id)
    return {"scan_id": scan_id, "tool": "zap", "result": result}


@router.post("/appsec/sbom")
async def run_sbom_scan(body: SBOMRequest) -> dict:
    """Generate SBOM and scan for vulnerabilities."""
    from kryon.tools.appsec.sbom import generate_sbom

    result = await generate_sbom.on_invoke_tool(None, body.model_dump_json())
    scan_id = uuid.uuid4().hex[:12]
    logger.info("SBOM scan completed: id=%s", scan_id)
    return {"scan_id": scan_id, "tool": "syft", "result": result}
