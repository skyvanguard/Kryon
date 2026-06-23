"""Client management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import get_accessible_client_ids, require_resource_access
from kryon.server.auth.models import User
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import ClientCreate, ClientUpdate

logger = get_logger(__name__)

router = APIRouter(tags=["clients"], dependencies=[Depends(require_api_key)])


def _guard(user: User | None, client_id: str) -> None:
    """Cross-client (BOLA/IDOR) guard. No-op under single-tenant API-key mode
    (user is None → full access); enforces ownership when JWT auth is active."""
    require_resource_access(user, client_id, get_store(), kind="Client", resource_id=client_id)


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
async def list_clients(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> list[dict]:
    """List clients accessible to the caller (all of them under single-tenant API-key mode)."""
    accessible = get_accessible_client_ids(user, get_store())
    clients = get_store().list_clients(offset=offset, limit=limit)
    if accessible is not None:
        clients = [c for c in clients if c.id in accessible]
    return [c.model_dump() for c in clients]


@router.get("/clients/{client_id}")
async def get_client(client_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Get a client by ID."""
    _guard(user, client_id)
    client = get_store().get_client(client_id)
    if not client:
        logger.warning("Client not found: %s", client_id)
        raise not_found("Client", client_id)
    return client.model_dump()


@router.put("/clients/{client_id}")
async def update_client(client_id: str, req: ClientUpdate, user: User | None = Depends(get_current_user)) -> dict:
    """Update a client."""
    _guard(user, client_id)
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
async def delete_client(client_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Delete a client and all associated data."""
    _guard(user, client_id)
    if not get_store().delete_client(client_id):
        logger.warning("Client not found for delete: %s", client_id)
        raise not_found("Client", client_id)
    logger.info("Client deleted: %s", client_id)
    return {"deleted": True}


@router.get("/clients/{client_id}/progress")
async def get_progress(client_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Get client risk progression data."""
    _guard(user, client_id)
    return _get_manager().get_client_progress(client_id)


@router.get("/clients/{client_id}/findings")
async def get_findings(
    client_id: str, status: str | None = None, user: User | None = Depends(get_current_user)
) -> list[dict]:
    """Get all findings for a client."""
    _guard(user, client_id)
    findings = get_store().get_client_findings(client_id, status=status)
    return [f.model_dump() for f in findings]


@router.get("/clients/{client_id}/scans")
async def get_scans(
    client_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> list[dict]:
    """Get scan history for a client."""
    _guard(user, client_id)
    return [s.model_dump() for s in get_store().list_scans(client_id, offset=offset, limit=limit)]


@router.get("/clients/{client_id}/timeline")
async def get_timeline(client_id: str, user: User | None = Depends(get_current_user)) -> list[dict]:
    """Get chronological timeline for a client."""
    _guard(user, client_id)
    return _get_manager().get_client_timeline(client_id)
