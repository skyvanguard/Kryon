"""Validation API routes — attack simulation, detection validation, coverage, and EVE exploit validation."""

from __future__ import annotations

import json
import uuid
from collections import OrderedDict
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger
from kryon.server.models import DetectRequest, SimulateRequest

logger = get_logger(__name__)

router = APIRouter(tags=["validation"], dependencies=[Depends(require_api_key)])

# ---------------------------------------------------------------------------
# EVE (Exploit Validation Engine) — Pydantic models
# ---------------------------------------------------------------------------


class ValidateRequest(BaseModel):
    """Request to validate a single security finding."""

    finding_id: str = Field(..., description="Unique identifier for the finding")
    finding_type: str = Field(..., description="Type of finding (sqli, xss, rce, auth_bypass, etc.)")
    target: str = Field(..., description="Target URL or host to validate against")
    parameter: str = Field("", description="Specific parameter to test")
    extra_context: str = Field("", description="Additional context for validation")


class ValidateResponse(BaseModel):
    """Response after submitting a finding for validation."""

    finding_id: str
    status: str = "queued"


class ValidationResult(BaseModel):
    """Full validation result for a finding."""

    finding_id: str
    status: str
    validation_status: Optional[str] = None
    exploit_proof: Optional[str] = None
    validation_method: Optional[str] = None
    details: Optional[str] = None


class ValidateBatchRequest(BaseModel):
    """Request to validate multiple findings at once."""

    findings: list[ValidateRequest] = Field(..., description="List of findings to validate")


class ValidateBatchResponse(BaseModel):
    """Response after submitting a batch of findings for validation."""

    results: list[ValidateResponse]


# In-memory store for validation results (keyed by finding_id, bounded)
_MAX_VALIDATION_RESULTS = 10_000
_validation_results: OrderedDict[str, ValidationResult] = OrderedDict()


# ---------------------------------------------------------------------------
# EVE background task
# ---------------------------------------------------------------------------


async def _run_validation(finding: ValidateRequest) -> None:
    """Run exploit validation in the background and store the result."""
    try:
        from kryon.tools.validation.exploit_validator import validate_finding

        result_json = await validate_finding.on_invoke_tool(
            None,
            json.dumps(
                {
                    "finding_title": finding.finding_id,
                    "finding_type": finding.finding_type,
                    "target": finding.target,
                    "parameter": finding.parameter,
                    "extra_context": finding.extra_context,
                }
            ),
        )

        try:
            parsed = json.loads(result_json)
        except (json.JSONDecodeError, TypeError):
            parsed = {"raw": result_json}

        _validation_results[finding.finding_id] = ValidationResult(
            finding_id=finding.finding_id,
            status="completed",
            validation_status=parsed.get("validation_status"),
            exploit_proof=parsed.get("exploit_proof"),
            validation_method=parsed.get("validation_method"),
            details=parsed.get("details"),
        )
        while len(_validation_results) > _MAX_VALIDATION_RESULTS:
            _validation_results.popitem(last=False)
        logger.info(
            "EVE validation completed: finding_id=%s status=%s",
            finding.finding_id,
            parsed.get("validation_status", "unknown"),
        )
    except Exception:
        _validation_results[finding.finding_id] = ValidationResult(
            finding_id=finding.finding_id,
            status="error",
            details="Validation failed due to an internal error",
        )
        logger.exception("EVE validation failed: finding_id=%s", finding.finding_id)


# ---------------------------------------------------------------------------
# EVE API routes
# ---------------------------------------------------------------------------


@router.post("/validate", status_code=202)
async def submit_validation(
    body: ValidateRequest,
    background_tasks: BackgroundTasks,
) -> ValidateResponse:
    """Submit a security finding for exploit validation (EVE).

    The validation runs asynchronously in the background.
    Use GET /validate/{finding_id} to retrieve the result.
    """
    _validation_results[body.finding_id] = ValidationResult(
        finding_id=body.finding_id,
        status="queued",
    )
    while len(_validation_results) > _MAX_VALIDATION_RESULTS:
        _validation_results.popitem(last=False)
    background_tasks.add_task(_run_validation, body)
    logger.info(
        "EVE validation queued: finding_id=%s type=%s target=%s",
        body.finding_id,
        body.finding_type,
        body.target,
    )
    return ValidateResponse(finding_id=body.finding_id, status="queued")


@router.get("/validate/{finding_id}")
async def get_validation_result(finding_id: str) -> ValidationResult:
    """Get the validation result for a finding by its ID."""
    result = _validation_results.get(finding_id)
    if result is None:
        logger.warning("EVE validation result not found: finding_id=%s", finding_id)
        raise HTTPException(status_code=404, detail=f"Validation result not found for finding_id={finding_id}")
    return result


@router.post("/validate/batch", status_code=202)
async def submit_batch_validation(
    body: ValidateBatchRequest,
    background_tasks: BackgroundTasks,
) -> ValidateBatchResponse:
    """Submit multiple findings for exploit validation (EVE).

    Each finding is validated independently in the background.
    Use GET /validate/{finding_id} to retrieve individual results.
    """
    results: list[ValidateResponse] = []
    for finding in body.findings:
        _validation_results[finding.finding_id] = ValidationResult(
            finding_id=finding.finding_id,
            status="queued",
        )
        while len(_validation_results) > _MAX_VALIDATION_RESULTS:
            _validation_results.popitem(last=False)
        background_tasks.add_task(_run_validation, finding)
        results.append(ValidateResponse(finding_id=finding.finding_id, status="queued"))
        logger.info(
            "EVE batch validation queued: finding_id=%s type=%s",
            finding.finding_id,
            finding.finding_type,
        )
    return ValidateBatchResponse(results=results)


@router.post("/validation/simulate")
async def simulate_attack(body: SimulateRequest) -> dict:
    """Simulate a MITRE ATT&CK technique."""
    from kryon.tools.validation.attack_simulator import simulate_attack as _simulate

    result = await _simulate.on_invoke_tool(None, body.model_dump_json())
    sim_id = uuid.uuid4().hex[:12]
    logger.info("Attack simulation completed: id=%s technique=%s", sim_id, body.technique_id)
    return {"simulation_id": sim_id, "technique_id": body.technique_id, "result": result}


@router.post("/validation/detect")
async def validate_detection(body: DetectRequest) -> dict:
    """Validate SIEM detection for a technique."""
    from kryon.tools.validation.detection_validator import validate_detection as _validate

    result = await _validate.on_invoke_tool(None, body.model_dump_json())
    logger.info("Detection validation completed: technique=%s", body.technique_id)
    return {"technique_id": body.technique_id, "result": result}


@router.get("/validation/coverage")
async def get_coverage(
    client_id: str = Query("", description="Client ID for scoped coverage"),
) -> dict:
    """Get MITRE ATT&CK coverage statistics."""
    from kryon.server.deps import get_store

    store = get_store()
    findings = store.list_all_findings(client_id=client_id or None, limit=500)
    findings_data = []
    for f in findings:
        try:
            parsed = json.loads(f.finding_json) if f.finding_json else {}
            findings_data.append(parsed)
        except json.JSONDecodeError:
            continue

    from kryon.tools.validation.coverage_scorer import calculate_mitre_coverage

    result = await calculate_mitre_coverage.on_invoke_tool(
        None,
        json.dumps({"findings_json": json.dumps(findings_data)}),
    )

    try:
        return json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return {"raw": result}
