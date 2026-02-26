"""Client management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from kryon.server.auth import require_api_key

router = APIRouter(tags=["clients"], dependencies=[Depends(require_api_key)])

import threading

# Lazy singleton (thread-safe)
_store = None
_store_lock = threading.Lock()


def _get_store():
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                from kryon.memory.store import MemoryStore

                _store = MemoryStore()
    return _store


def _get_manager():
    from kryon.memory.client_manager import ClientManager

    return ClientManager(_get_store())


class ClientCreate(BaseModel):
    name: str
    scope: list[str] = []
    contact: str = ""
    notes: str = ""
    tags: list[str] = []


class ClientUpdate(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    contact: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


@router.post("/clients")
async def create_client(req: ClientCreate) -> dict:
    """Create a new client."""
    from kryon.memory.models import Client

    client = Client(**req.model_dump())
    _get_store().create_client(client)
    return client.model_dump()


@router.get("/clients")
async def list_clients() -> list[dict]:
    """List all clients."""
    return [c.model_dump() for c in _get_store().list_clients()]


@router.get("/clients/{client_id}")
async def get_client(client_id: str) -> dict:
    """Get a client by ID."""
    client = _get_store().get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client.model_dump()


@router.put("/clients/{client_id}")
async def update_client(client_id: str, req: ClientUpdate) -> dict:
    """Update a client."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    client = _get_store().update_client(client_id, **updates)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client.model_dump()


@router.delete("/clients/{client_id}")
async def delete_client(client_id: str) -> dict:
    """Delete a client and all associated data."""
    if not _get_store().delete_client(client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    return {"deleted": True}


@router.get("/clients/{client_id}/progress")
async def get_progress(client_id: str) -> dict:
    """Get client risk progression data."""
    return _get_manager().get_client_progress(client_id)


@router.get("/clients/{client_id}/findings")
async def get_findings(client_id: str, status: str | None = None) -> list[dict]:
    """Get all findings for a client."""
    findings = _get_store().get_client_findings(client_id, status=status)
    return [f.model_dump() for f in findings]


@router.get("/clients/{client_id}/scans")
async def get_scans(client_id: str) -> list[dict]:
    """Get scan history for a client."""
    return [s.model_dump() for s in _get_store().list_scans(client_id)]


@router.get("/clients/{client_id}/timeline")
async def get_timeline(client_id: str) -> list[dict]:
    """Get chronological timeline for a client."""
    return _get_manager().get_client_timeline(client_id)
