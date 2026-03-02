"""Client management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import ClientCreate, ClientUpdate

logger = get_logger(__name__)

router = APIRouter(tags=["clients"], dependencies=[Depends(require_api_key)])


def _get_manager():
    from kryon.memory.client_manager import ClientManager

    return ClientManager(get_store())


@router.post("/clients")
async def create_client(req: ClientCreate) -> dict:
    """Create a new client."""
    from kryon.memory.models import Client

    client = Client(**req.model_dump())
    get_store().create_client(client)
    logger.info("Client created: %s", client.name)
    return client.model_dump()


@router.get("/clients")
async def list_clients(offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    """List all clients."""
    return [c.model_dump() for c in get_store().list_clients(offset=offset, limit=limit)]


@router.get("/clients/{client_id}")
async def get_client(client_id: str) -> dict:
    """Get a client by ID."""
    client = get_store().get_client(client_id)
    if not client:
        logger.warning("Client not found: %s", client_id)
        raise not_found("Client", client_id)
    return client.model_dump()


@router.put("/clients/{client_id}")
async def update_client(client_id: str, req: ClientUpdate) -> dict:
    """Update a client."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    client = get_store().update_client(client_id, **updates)
    if not client:
        logger.warning("Client not found for update: %s", client_id)
        raise not_found("Client", client_id)
    logger.info("Client updated: %s", client_id)
    return client.model_dump()


@router.delete("/clients/{client_id}")
async def delete_client(client_id: str) -> dict:
    """Delete a client and all associated data."""
    if not get_store().delete_client(client_id):
        logger.warning("Client not found for delete: %s", client_id)
        raise not_found("Client", client_id)
    logger.info("Client deleted: %s", client_id)
    return {"deleted": True}


@router.get("/clients/{client_id}/progress")
async def get_progress(client_id: str) -> dict:
    """Get client risk progression data."""
    return _get_manager().get_client_progress(client_id)


@router.get("/clients/{client_id}/findings")
async def get_findings(client_id: str, status: str | None = None) -> list[dict]:
    """Get all findings for a client."""
    findings = get_store().get_client_findings(client_id, status=status)
    return [f.model_dump() for f in findings]


@router.get("/clients/{client_id}/scans")
async def get_scans(client_id: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    """Get scan history for a client."""
    return [s.model_dump() for s in get_store().list_scans(client_id, offset=offset, limit=limit)]


@router.get("/clients/{client_id}/timeline")
async def get_timeline(client_id: str) -> list[dict]:
    """Get chronological timeline for a client."""
    return _get_manager().get_client_timeline(client_id)
