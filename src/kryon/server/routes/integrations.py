"""SIEM integration management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.rbac import require_permission
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["integrations"], dependencies=[Depends(require_api_key)])


class CreateSIEMConfigRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    siem_type: str = Field(..., pattern="^(splunk|qradar|elastic)$")
    endpoint: str = Field(..., min_length=1, max_length=2000)
    token: str = Field("", max_length=500)
    index_name: str = Field("", max_length=200)
    enabled: bool = True
    config_json: dict = {}


class SIEMConfigResponse(BaseModel):
    id: str
    name: str
    siem_type: str
    endpoint: str
    index_name: str
    enabled: bool
    created_at: str


@router.post(
    "/integrations/siem",
    response_model=SIEMConfigResponse,
    dependencies=[Depends(require_permission("integrations:write"))],
)
async def create_siem_config(req: CreateSIEMConfigRequest) -> SIEMConfigResponse:
    """Create a new SIEM integration configuration."""
    store = get_store()
    config_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    store.create_siem_config(
        {
            "id": config_id,
            "name": req.name,
            "siem_type": req.siem_type,
            "endpoint": req.endpoint,
            "token": req.token,
            "index_name": req.index_name,
            "enabled": req.enabled,
            "config_json": req.config_json,
            "created_at": now,
        }
    )
    logger.info("SIEM config created: id=%s type=%s name=%s", config_id, req.siem_type, req.name)
    return SIEMConfigResponse(
        id=config_id,
        name=req.name,
        siem_type=req.siem_type,
        endpoint=req.endpoint,
        index_name=req.index_name,
        enabled=req.enabled,
        created_at=now,
    )


@router.get("/integrations/siem", dependencies=[Depends(require_permission("integrations:read"))])
async def list_siem_configs() -> list[SIEMConfigResponse]:
    """List all SIEM configurations."""
    store = get_store()
    configs = store.list_siem_configs()
    return [
        SIEMConfigResponse(
            id=c["id"],
            name=c["name"],
            siem_type=c["siem_type"],
            endpoint=c["endpoint"],
            index_name=c.get("index_name", ""),
            enabled=bool(c.get("enabled", True)),
            created_at=c["created_at"],
        )
        for c in configs
    ]


@router.delete("/integrations/siem/{config_id}", dependencies=[Depends(require_permission("integrations:write"))])
async def delete_siem_config(config_id: str) -> dict:
    """Delete a SIEM configuration."""
    store = get_store()
    deleted = store.delete_siem_config(config_id)
    if not deleted:
        logger.warning("SIEM config not found for delete: %s", config_id)
        raise not_found("SIEM config", config_id)
    logger.info("SIEM config deleted: %s", config_id)
    return {"deleted": True, "id": config_id}
