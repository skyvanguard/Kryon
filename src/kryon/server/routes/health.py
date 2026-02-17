"""Health check endpoint."""

from fastapi import APIRouter, Depends

from kryon.server.auth import require_api_key
from kryon.server.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint returning server status and version."""
    from kryon.agents import get_available_agents

    agents = get_available_agents()
    return HealthResponse(
        status="ok",
        version="1.0.0",
        agents_count=len(agents),
    )
