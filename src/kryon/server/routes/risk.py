"""Business risk scoring API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["risk"], dependencies=[Depends(require_api_key)])


@router.get("/risk/overview")
async def risk_overview(client_id: str = "") -> dict:
    """Get aggregated risk overview with impact breakdown."""
    from kryon.evaluation.business_risk import BusinessRiskScorer

    store = get_store()
    scorer = BusinessRiskScorer()
    return scorer.get_risk_overview(store, client_id=client_id)


@router.get("/risk/assets")
async def risky_assets(client_id: str = "", limit: int = Query(10, ge=1, le=100)) -> dict:
    """Get top risky assets with contextual scores."""
    from kryon.evaluation.business_risk import BusinessRiskScorer

    store = get_store()
    scorer = BusinessRiskScorer()
    assets = store.get_assets_with_findings(client_id=client_id, limit=limit)

    scored = []
    for a in assets:
        criticality = a.get("criticality", "medium")
        exposure = a.get("exposure", "internal")
        finding_count = a.get("finding_count", 0)
        # Synthetic finding for scoring
        score = scorer.calculate_contextual_risk(
            {"severity": "high" if finding_count > 3 else "medium"},
            asset_criticality=criticality,
            exposure_level=exposure,
        )
        scored.append({**a, "risk_score": score})

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"items": scored}


@router.get("/risk/trend")
async def risk_trend(client_id: str = "", days: int = Query(90, ge=7, le=365)) -> dict:
    """Get risk score trend over time (simplified — based on finding dates)."""
    store = get_store()
    from datetime import datetime, timedelta, timezone

    end = datetime.now(timezone.utc)
    end - timedelta(days=days)

    findings = store.list_all_findings(client_id=client_id or None, limit=1000)
    # Group by week
    from collections import defaultdict

    weekly: dict[str, int] = defaultdict(int)
    for f in findings:
        try:
            dt = datetime.fromisoformat(f.first_seen)
            week = dt.strftime("%Y-W%W")
            weekly[week] += 1
        except (ValueError, TypeError):
            continue

    data_points = [{"week": k, "finding_count": v} for k, v in sorted(weekly.items())]
    return {"data_points": data_points, "days": days}
