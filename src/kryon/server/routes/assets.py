"""Assets API routes — asset inventory management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found

router = APIRouter(tags=["assets"], dependencies=[Depends(require_api_key)])


@router.get("/assets")
async def list_assets(
    query: str = "",
    asset_type: str = "",
    client_id: str = "",
    status: str = "",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    """List assets with optional filtering."""
    store = get_store()
    items = store.list_assets(query=query, asset_type=asset_type, client_id=client_id, status=status, offset=offset, limit=limit)
    return {"items": items, "total": len(items), "offset": offset, "limit": limit}


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: str) -> dict:
    """Get a specific asset."""
    store = get_store()
    asset = store.get_asset(asset_id)
    if not asset:
        raise not_found("Asset", asset_id)
    return asset


@router.get("/assets/{asset_id}/timeline")
async def get_asset_timeline(asset_id: str) -> dict:
    """Get asset change timeline."""
    store = get_store()
    asset = store.get_asset(asset_id)
    if not asset:
        raise not_found("Asset", asset_id)
    timeline = store.get_asset_timeline(asset_id)
    return {"asset_id": asset_id, "changes": timeline}


@router.post("/assets")
async def create_asset(body: dict) -> dict:
    """Register a new asset."""
    import uuid
    from datetime import datetime, timezone

    store = get_store()
    asset_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    store.upsert_asset(
        asset_id=asset_id,
        asset_type=body.get("asset_type", "unknown"),
        identifier=body.get("identifier", ""),
        client_id=body.get("client_id", ""),
        metadata_json=body.get("metadata_json", "{}"),
        now=now,
    )
    return {"id": asset_id, "status": "created"}


@router.put("/assets/{asset_id}")
async def update_asset(asset_id: str, body: dict) -> dict:
    """Update an asset."""
    store = get_store()
    asset = store.get_asset(asset_id)
    if not asset:
        raise not_found("Asset", asset_id)

    conn = store._get_conn()
    allowed = {"status", "metadata_json"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if updates:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(f"UPDATE assets SET {set_clause} WHERE id = ?", (*updates.values(), asset_id))
        conn.commit()

    return {"id": asset_id, "status": "updated"}
