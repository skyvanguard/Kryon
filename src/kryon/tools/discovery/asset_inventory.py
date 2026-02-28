"""Asset inventory management — register, search, and track asset changes."""

import json
import uuid
from datetime import datetime, timezone

from kryon.sdk.agents import function_tool


@function_tool
def register_asset(
    asset_type: str,
    identifier: str,
    metadata_json: str = "{}",
    client_id: str = "",
    ctf=None,
) -> str:
    """
    Register a discovered asset in the inventory.

    Args:
        asset_type: Asset type (domain, subdomain, ip, service, certificate, cloud_resource)
        identifier: Unique identifier (e.g. IP address, domain name)
        metadata_json: JSON string with additional metadata
        client_id: Associated client ID
        ctf: CTF context

    Returns:
        str: Registration result with asset ID
    """
    try:
        from kryon.server.deps import get_store
        store = get_store()
        asset_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        store.upsert_asset(asset_id, asset_type, identifier, client_id, metadata_json, now)
        return json.dumps({"asset_id": asset_id, "status": "registered", "identifier": identifier})
    except Exception as e:
        return json.dumps({"asset_id": uuid.uuid4().hex[:12], "status": "registered_local", "identifier": identifier, "note": str(e)})


@function_tool
def search_assets(
    query: str = "",
    asset_type: str = "",
    client_id: str = "",
    status: str = "",
    ctf=None,
) -> str:
    """
    Search the asset inventory.

    Args:
        query: Search query (matches identifier)
        asset_type: Filter by asset type
        client_id: Filter by client ID
        status: Filter by status (active, inactive, decommissioned)
        ctf: CTF context

    Returns:
        str: JSON list of matching assets
    """
    try:
        from kryon.server.deps import get_store
        store = get_store()
        assets = store.list_assets(query=query, asset_type=asset_type, client_id=client_id, status=status)
        return json.dumps(assets, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "note": "Asset database not available"})


@function_tool
def asset_timeline(
    asset_id: str,
    ctf=None,
) -> str:
    """
    Get the change timeline for a specific asset.

    Args:
        asset_id: Asset ID to query
        ctf: CTF context

    Returns:
        str: JSON timeline of asset changes
    """
    try:
        from kryon.server.deps import get_store
        store = get_store()
        timeline = store.get_asset_timeline(asset_id)
        return json.dumps(timeline, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "asset_id": asset_id})
