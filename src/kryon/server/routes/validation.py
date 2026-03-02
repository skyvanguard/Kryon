"""Validation API routes — attack simulation, detection validation, coverage."""

from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger
from kryon.server.models import DetectRequest, SimulateRequest

logger = get_logger(__name__)

router = APIRouter(tags=["validation"], dependencies=[Depends(require_api_key)])


@router.post("/validation/simulate")
async def simulate_attack(body: SimulateRequest) -> dict:
    """Simulate a MITRE ATT&CK technique."""
    from kryon.tools.validation.attack_simulator import simulate_attack as _simulate

    result = await asyncio.to_thread(
        _simulate.on_invoke_tool,
        None,
        body.model_dump_json(),
    )
    sim_id = uuid.uuid4().hex[:12]
    logger.info("Attack simulation completed: id=%s technique=%s", sim_id, body.technique_id)
    return {"simulation_id": sim_id, "technique_id": body.technique_id, "result": result}


@router.post("/validation/detect")
async def validate_detection(body: DetectRequest) -> dict:
    """Validate SIEM detection for a technique."""
    from kryon.tools.validation.detection_validator import validate_detection as _validate

    result = await asyncio.to_thread(
        _validate.on_invoke_tool,
        None,
        body.model_dump_json(),
    )
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

    result = await asyncio.to_thread(
        calculate_mitre_coverage.on_invoke_tool,
        None,
        json.dumps({"findings_json": json.dumps(findings_data)}),
    )

    try:
        return json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return {"raw": result}
