"""VM Scanner Integration routes — import findings from Qualys, Tenable, Rapid7, nmap, nuclei."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections import OrderedDict

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["vm-integration"], dependencies=[Depends(require_api_key)])

# In-memory job tracking (bounded, thread-safe via asyncio.Lock)
_MAX_IMPORT_JOBS = 1_000
_import_jobs: OrderedDict[str, dict] = OrderedDict()
_import_jobs_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ImportQualysRequest(BaseModel):
    """Request to import findings from Qualys."""

    api_url: str = Field(..., description="Qualys API URL")
    api_key: str = Field(..., description="Qualys API key")
    scan_id: str = Field("", description="Optional scan ID filter")
    auto_validate: bool = Field(False, description="Auto-validate with EVE")


class ImportTenableRequest(BaseModel):
    """Request to import findings from Tenable.io."""

    api_url: str = Field(..., description="Tenable.io API URL")
    access_key: str = Field(..., description="Tenable access key")
    secret_key: str = Field(..., description="Tenable secret key")
    scan_id: str = Field("", description="Optional scan ID filter")
    auto_validate: bool = Field(False, description="Auto-validate with EVE")


class ImportRapid7Request(BaseModel):
    """Request to import findings from Rapid7 InsightVM."""

    api_url: str = Field(..., description="Rapid7 InsightVM API URL")
    api_key: str = Field(..., description="Rapid7 API key")
    site_id: str = Field("", description="Optional site ID filter")
    auto_validate: bool = Field(False, description="Auto-validate with EVE")


class ImportFileRequest(BaseModel):
    """Request to import findings from a local file (nmap XML or nuclei JSONL)."""

    file_path: str = Field(..., description="Path to nmap XML or nuclei JSONL file")
    source_type: Literal["nmap", "nuclei"] = Field("nmap", description="File type: nmap or nuclei")
    auto_validate: bool = Field(False, description="Auto-validate with EVE")

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        """Reject path traversal and validate file extension."""
        if ".." in v:
            raise ValueError("Path traversal not allowed")
        from pathlib import Path

        resolved = Path(v).resolve()
        if resolved.suffix not in (".xml", ".jsonl"):
            raise ValueError("Only .xml and .jsonl files are supported")
        return str(resolved)


class ImportResponse(BaseModel):
    """Response after submitting an import job."""

    job_id: str
    status: str = "queued"
    source: str
    message: str = "Import job queued"


# ---------------------------------------------------------------------------
# Background import runner
# ---------------------------------------------------------------------------


class _ToolContext:
    """Minimal context for tool invocation from routes."""

    context = None


async def _run_import(job_id: str, source: str, params: dict) -> None:
    """Run import in background and update job status."""
    async with _import_jobs_lock:
        _import_jobs[job_id]["status"] = "running"
    try:
        ctx = _ToolContext()
        if source == "qualys":
            from kryon.tools.intelligence.vm_importers import import_qualys_findings

            result = await import_qualys_findings.on_invoke_tool(ctx, json.dumps(params))
        elif source == "tenable":
            from kryon.tools.intelligence.vm_importers import import_tenable_findings

            result = await import_tenable_findings.on_invoke_tool(ctx, json.dumps(params))
        elif source == "rapid7":
            from kryon.tools.intelligence.vm_importers import import_rapid7_findings

            result = await import_rapid7_findings.on_invoke_tool(ctx, json.dumps(params))
        elif source == "nmap":
            from kryon.tools.intelligence.vm_importers import import_nmap_xml

            result = await import_nmap_xml.on_invoke_tool(ctx, json.dumps(params))
        elif source == "nuclei":
            from kryon.tools.intelligence.vm_importers import import_nuclei_jsonl

            result = await import_nuclei_jsonl.on_invoke_tool(ctx, json.dumps(params))
        else:
            raise ValueError(f"Unknown source: {source}")

        parsed = json.loads(result) if isinstance(result, str) else result
        async with _import_jobs_lock:
            _import_jobs[job_id].update(
                {
                    "status": "completed",
                    "findings_count": parsed.get("count", 0),
                    "result": parsed,
                }
            )
        logger.info(
            "Import job %s completed: source=%s findings=%d",
            job_id,
            source,
            parsed.get("count", 0),
        )
    except Exception as exc:
        logger.error("Import job %s failed: %s", job_id, exc, exc_info=True)
        async with _import_jobs_lock:
            _import_jobs[job_id].update(
                {
                    "status": "failed",
                    "error": str(exc),
                }
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _register_job(job_id: str, source: str) -> None:
    """Register a new job with bounded eviction."""
    async with _import_jobs_lock:
        _import_jobs[job_id] = {"job_id": job_id, "status": "queued", "source": source}
        while len(_import_jobs) > _MAX_IMPORT_JOBS:
            _import_jobs.popitem(last=False)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/import/qualys", response_model=ImportResponse, status_code=202)
async def import_qualys(req: ImportQualysRequest, bg: BackgroundTasks):
    """Import vulnerability findings from Qualys scanner."""
    job_id = uuid.uuid4().hex[:12]
    await _register_job(job_id, "qualys")
    bg.add_task(
        _run_import,
        job_id,
        "qualys",
        {"api_url": req.api_url, "api_key": req.api_key, "scan_id": req.scan_id},
    )
    logger.info("Qualys import queued: job_id=%s scan_id=%s", job_id, req.scan_id)
    return ImportResponse(job_id=job_id, source="qualys")


@router.post("/import/tenable", response_model=ImportResponse, status_code=202)
async def import_tenable(req: ImportTenableRequest, bg: BackgroundTasks):
    """Import vulnerability findings from Tenable.io scanner."""
    job_id = uuid.uuid4().hex[:12]
    await _register_job(job_id, "tenable")
    bg.add_task(
        _run_import,
        job_id,
        "tenable",
        {
            "api_url": req.api_url,
            "access_key": req.access_key,
            "secret_key": req.secret_key,
            "scan_id": req.scan_id,
        },
    )
    logger.info("Tenable import queued: job_id=%s", job_id)
    return ImportResponse(job_id=job_id, source="tenable")


@router.post("/import/rapid7", response_model=ImportResponse, status_code=202)
async def import_rapid7(req: ImportRapid7Request, bg: BackgroundTasks):
    """Import vulnerability findings from Rapid7 InsightVM."""
    job_id = uuid.uuid4().hex[:12]
    await _register_job(job_id, "rapid7")
    bg.add_task(
        _run_import,
        job_id,
        "rapid7",
        {"api_url": req.api_url, "api_key": req.api_key, "site_id": req.site_id},
    )
    logger.info("Rapid7 import queued: job_id=%s", job_id)
    return ImportResponse(job_id=job_id, source="rapid7")


@router.post("/import/file", response_model=ImportResponse, status_code=202)
async def import_file(req: ImportFileRequest, bg: BackgroundTasks):
    """Import vulnerability findings from a local nmap XML or nuclei JSONL file."""
    job_id = uuid.uuid4().hex[:12]
    source = req.source_type if req.source_type in ("nmap", "nuclei") else "nmap"
    await _register_job(job_id, source)
    if source == "nmap":
        bg.add_task(_run_import, job_id, "nmap", {"xml_file": req.file_path})
    else:
        bg.add_task(_run_import, job_id, "nuclei", {"jsonl_file": req.file_path})
    logger.info("File import queued: job_id=%s source=%s path=%s", job_id, source, req.file_path)
    return ImportResponse(job_id=job_id, source=source)


@router.get("/import/{job_id}")
async def get_import_status(job_id: str):
    """Get the status of an import job by its ID."""
    async with _import_jobs_lock:
        job = _import_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Import job {job_id} not found")
    return job
