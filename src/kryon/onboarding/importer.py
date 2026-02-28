"""Asset import and scope validation for onboarding."""

from __future__ import annotations

import csv
import io
import json
import logging
import socket
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def import_assets_csv(csv_data: str, client_id: str, store) -> int:
    """Import assets from CSV data. Returns count of imported assets.

    Expected CSV columns: identifier, asset_type, [metadata]
    """
    reader = csv.DictReader(io.StringIO(csv_data))
    count = 0
    now = datetime.now(timezone.utc).isoformat()

    for row in reader:
        identifier = row.get("identifier", "").strip()
        asset_type = row.get("asset_type", "host").strip()
        if not identifier:
            continue

        metadata = {k: v for k, v in row.items() if k not in ("identifier", "asset_type") and v}
        store.upsert_asset(
            asset_id=str(uuid.uuid4()),
            asset_type=asset_type,
            identifier=identifier,
            client_id=client_id,
            metadata_json=json.dumps(metadata),
            now=now,
        )
        count += 1

    logger.info("Imported %d assets from CSV for client %s", count, client_id)
    return count


def import_assets_json(json_data: str, client_id: str, store) -> int:
    """Import assets from JSON array. Returns count of imported assets.

    Expected format: [{"identifier": "...", "asset_type": "...", ...}]
    """
    try:
        assets = json.loads(json_data) if isinstance(json_data, str) else json_data
    except (json.JSONDecodeError, TypeError):
        return 0

    count = 0
    now = datetime.now(timezone.utc).isoformat()

    for asset in assets:
        identifier = asset.get("identifier", "").strip()
        asset_type = asset.get("asset_type", "host").strip()
        if not identifier:
            continue

        metadata = {k: v for k, v in asset.items() if k not in ("identifier", "asset_type")}
        store.upsert_asset(
            asset_id=str(uuid.uuid4()),
            asset_type=asset_type,
            identifier=identifier,
            client_id=client_id,
            metadata_json=json.dumps(metadata),
            now=now,
        )
        count += 1

    logger.info("Imported %d assets from JSON for client %s", count, client_id)
    return count


def validate_scope(targets: list[str]) -> list[dict]:
    """Validate target reachability via DNS resolution.

    Returns list of {target, reachable, ip, error}.
    """
    results = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        try:
            ip = socket.gethostbyname(target)
            results.append({"target": target, "reachable": True, "ip": ip, "error": ""})
        except socket.gaierror as e:
            results.append({"target": target, "reachable": False, "ip": "", "error": str(e)})
        except Exception as e:
            results.append({"target": target, "reachable": False, "ip": "", "error": str(e)})

    return results
