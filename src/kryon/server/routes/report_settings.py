"""Report branding and template configuration API routes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["report_settings"], dependencies=[Depends(require_api_key)])


class BrandingBody(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=100)
    logo_url: str = Field("", max_length=2000, pattern=r"^(https?://.*|)$")
    primary_color: str = Field("#00d4ff", max_length=20)
    company_name: str = Field("", max_length=200)
    footer_text: str = Field("", max_length=500)


@router.get("/reports/templates")
async def list_templates() -> list[dict]:
    """List available report templates."""
    from kryon.reporting.templates import list_templates

    return list_templates()


@router.post("/reports/branding")
async def save_branding(body: BrandingBody) -> dict:
    """Save or update branding config for a client."""
    store = get_store()
    now = datetime.now(timezone.utc).isoformat()
    existing = store.get_branding(body.client_id)
    branding_id = existing["id"] if existing else str(uuid.uuid4())
    store.save_branding(
        branding_id=branding_id,
        client_id=body.client_id,
        logo_url=body.logo_url,
        primary_color=body.primary_color,
        company_name=body.company_name,
        footer_text=body.footer_text,
        created_at=existing["created_at"] if existing else now,
    )
    logger.info("Branding saved: client=%s", body.client_id)
    return {"id": branding_id, "client_id": body.client_id}


@router.get("/reports/branding/{client_id}")
async def get_branding(client_id: str) -> dict:
    """Get branding config for a client."""
    store = get_store()
    branding = store.get_branding(client_id)
    if not branding:
        logger.warning("Branding not found: client=%s", client_id)
        raise not_found("Branding", client_id)
    return branding
