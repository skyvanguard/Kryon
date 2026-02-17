"""Usage and cost tracking endpoints."""

from fastapi import APIRouter, Depends

from kryon.server.auth import require_api_key
from kryon.server.models import DailyUsage, ModelUsage, UsageSummary

router = APIRouter(tags=["usage"], dependencies=[Depends(require_api_key)])


@router.get("/usage", response_model=UsageSummary)
async def get_usage_summary() -> UsageSummary:
    """Get global usage summary."""
    from kryon.sdk.agents.global_usage_tracker import GLOBAL_USAGE_TRACKER

    summary = GLOBAL_USAGE_TRACKER.get_summary()
    return UsageSummary(**summary)


@router.get("/usage/models", response_model=list[ModelUsage])
async def get_model_usage() -> list[ModelUsage]:
    """Get usage breakdown by model."""
    from kryon.sdk.agents.global_usage_tracker import GLOBAL_USAGE_TRACKER

    model_data = GLOBAL_USAGE_TRACKER.usage_data.get("model_usage", {})
    return [
        ModelUsage(
            model=model,
            total_cost=stats.get("total_cost", 0),
            total_input_tokens=stats.get("total_input_tokens", 0),
            total_output_tokens=stats.get("total_output_tokens", 0),
            total_requests=stats.get("total_requests", 0),
        )
        for model, stats in sorted(model_data.items(), key=lambda x: x[1].get("total_cost", 0), reverse=True)
    ]


@router.get("/usage/daily", response_model=list[DailyUsage])
async def get_daily_usage() -> list[DailyUsage]:
    """Get daily usage breakdown."""
    from kryon.sdk.agents.global_usage_tracker import GLOBAL_USAGE_TRACKER

    daily_data = GLOBAL_USAGE_TRACKER.usage_data.get("daily_usage", {})
    return [
        DailyUsage(
            date=date,
            total_cost=stats.get("total_cost", 0),
            total_input_tokens=stats.get("total_input_tokens", 0),
            total_output_tokens=stats.get("total_output_tokens", 0),
            total_requests=stats.get("total_requests", 0),
        )
        for date, stats in sorted(daily_data.items(), reverse=True)
    ]
