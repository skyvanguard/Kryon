"""Evaluation metrics API endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["evaluations"], dependencies=[Depends(require_api_key)])


@router.get("/evaluations/metrics")
async def get_metrics(findings_json: str = Query("[]")) -> dict:
    """Get evaluation metrics for a set of findings."""
    from kryon.evaluation.dashboard_metrics import DashboardMetrics
    from kryon.intelligence.models import Finding

    try:
        raw = json.loads(findings_json)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("Malformed JSON in /evaluations/metrics: %s", e)
        raise HTTPException(status_code=400, detail="Malformed JSON")
    try:
        findings = [Finding(**f) for f in raw]
    except Exception as e:
        logger.warning("Invalid finding data in /evaluations/metrics: %s", e)
        raise HTTPException(status_code=400, detail="Invalid finding data")

    metrics = DashboardMetrics()
    return metrics.compute(findings)


@router.get("/evaluations/compare")
async def compare_scans(
    before_json: str = Query("[]"),
    after_json: str = Query("[]"),
) -> dict:
    """Compare two sets of findings (before/after)."""
    from kryon.evaluation.comparator import ScanComparator
    from kryon.intelligence.models import Finding

    try:
        before_raw = json.loads(before_json)
        after_raw = json.loads(after_json)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("Malformed JSON in /evaluations/compare: %s", e)
        raise HTTPException(status_code=400, detail="Malformed JSON")
    try:
        before = [Finding(**f) for f in before_raw]
        after = [Finding(**f) for f in after_raw]
    except Exception as e:
        logger.warning("Invalid finding data in /evaluations/compare: %s", e)
        raise HTTPException(status_code=400, detail="Invalid finding data")

    comp = ScanComparator()
    result = comp.compare(before, after)
    return result.model_dump()


@router.get("/profiles")
async def list_profiles() -> list[dict]:
    """List available scan profiles."""
    from kryon.server.profiles import list_profiles

    return list_profiles()
