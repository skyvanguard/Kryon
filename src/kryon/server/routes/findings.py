"""Findings API — consolidated view of all security findings."""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import get_accessible_client_ids, require_resource_access
from kryon.server.auth.models import User
from kryon.server.auth.rbac import require_permission
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.services.program_metrics import compute_program_metrics
from kryon.state.baseline_diff import compute_diff

logger = get_logger(__name__)

router = APIRouter(tags=["findings"], dependencies=[Depends(require_api_key)])


@router.get("/findings")
async def list_findings(
    severity: str | None = None,
    status: str | None = None,
    client_id: str | None = None,
    tool_source: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> dict:
    """List all findings with optional filtering and pagination."""
    store = get_store()
    # Restrict non-admin users to their assigned clients. The store filters
    # by a single client_id, so we require one (and verify it) for scoped
    # users. Full multi-client list filtering needs store-level support
    # (tracked for the tenancy work) — single-tenant deployments are
    # unaffected since there is only one client.
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        if client_id is None:
            if len(accessible) == 1:
                client_id = next(iter(accessible))
            else:
                raise not_found("Findings", "scope")
        elif client_id not in accessible:
            raise not_found("Findings", client_id)
    items = store.list_all_findings(
        severity=severity,
        status=status,
        client_id=client_id,
        tool_source=tool_source,
        offset=offset,
        limit=limit,
    )
    total = store.count_findings(
        severity=severity,
        status=status,
        client_id=client_id,
        tool_source=tool_source,
    )
    return {
        "items": [f.model_dump() for f in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


def _load_scan_findings(store, scan_id: str) -> list[dict]:
    """Parse a scan's persisted findings into diff-ready dicts.

    Maps the stored field names onto the ``(rule_id, host)`` key the diff
    engine expects — findings persist ``affected_asset``/``cwe``/``title``,
    the engine keys on ``host``/``rule_id``. Tolerant of malformed rows.
    """
    out: list[dict] = []
    for fr in store.get_findings(scan_id):
        try:
            parsed = json.loads(fr.finding_json) if fr.finding_json else {}
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        if not isinstance(parsed, dict):
            continue
        host = parsed.get("host") or parsed.get("affected_asset") or parsed.get("affected") or ""
        rule_id = parsed.get("rule_id") or parsed.get("cwe") or parsed.get("title") or ""
        out.append(
            {
                "rule_id": rule_id,
                "host": host,
                "severity": parsed.get("severity", "info"),
                "evidence": parsed.get("evidence") or parsed.get("description") or "",
                "title": parsed.get("title") or parsed.get("name") or rule_id,
                "remediation": parsed.get("remediation", ""),
            }
        )
    return out


# NOTE: this route MUST be declared before ``/findings/{finding_id}`` so the
# literal segment "drift" is not captured as a finding id by the path param.
@router.get("/findings/drift")
async def findings_drift(
    client_id: str | None = None,
    user: User | None = Depends(get_current_user),
) -> dict:
    """Baseline drift between the two most recent scans for a client.

    This is what turns Kryon from a scanner into a monitor — the client
    sees what is NEW (alert), GONE (remediated) and CHANGED since the
    previous scan, instead of a static once-a-year snapshot.
    """
    store = get_store()
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        if client_id is None:
            if len(accessible) == 1:
                client_id = next(iter(accessible))
            else:
                raise not_found("Findings", "scope")
        elif client_id not in accessible:
            raise not_found("Findings", client_id)

    scans = store.list_scans(client_id=client_id, limit=2)
    if len(scans) < 2:
        # First-ever (or only) scan — warm-up, no baseline to compare against.
        return {
            "baseline": False,
            "message": "Se necesita al menos un análisis previo para comparar el drift.",
            "current_scan": scans[0].started_at if scans else None,
            "previous_scan": None,
            "summary": {"new": 0, "gone": 0, "changed": 0, "stable": 0},
            "new": [],
            "gone": [],
            "changed": [],
            "stable": [],
        }

    current_scan, previous_scan = scans[0], scans[1]
    curr = _load_scan_findings(store, current_scan.id)
    prev = _load_scan_findings(store, previous_scan.id)
    result = compute_diff(prev, curr).to_dict()
    result["baseline"] = True
    result["current_scan"] = current_scan.started_at
    result["previous_scan"] = previous_scan.started_at
    logger.info(
        "Drift computed: client=%s new=%d gone=%d changed=%d",
        client_id,
        result["summary"]["new"],
        result["summary"]["gone"],
        result["summary"]["changed"],
    )
    return result


# Declared before ``/findings/{finding_id}`` so "metrics" is not captured as an id.
@router.get("/findings/metrics")
async def findings_metrics(
    client_id: str | None = None,
    user: User | None = Depends(get_current_user),
) -> dict:
    """Program metrics — the XBOW shift from finding-count to validated-exploitable.

    Returns the funnel (candidatos -> validados explotables -> mitigados) plus the
    verification-band and status breakdown, so the client sees signal, not volume.
    """
    store = get_store()
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        if client_id is None:
            if len(accessible) == 1:
                client_id = next(iter(accessible))
            else:
                raise not_found("Findings", "scope")
        elif client_id not in accessible:
            raise not_found("Findings", client_id)

    records: list[dict] = []
    for fr in store.list_all_findings(client_id=client_id, limit=1000):
        try:
            parsed = json.loads(fr.finding_json) if fr.finding_json else {}
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        records.append(
            {
                "severity": parsed.get("severity"),
                "verification_level": parsed.get("verification_level", "confirmed"),
                "needs_verification": parsed.get("needs_verification", False),
                "status": fr.status,
                "cwe": parsed.get("cwe") or parsed.get("cwe_id") or "",
            }
        )
    return compute_program_metrics(records)


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Get a specific finding by ID."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    return finding.model_dump()


class UpdateFindingStatus(BaseModel):
    status: Literal["open", "remediated", "accepted", "false_positive"]


@router.put("/findings/{finding_id}/status", dependencies=[Depends(require_permission("findings:write"))])
async def update_finding_status(
    finding_id: str, body: UpdateFindingStatus, user: User | None = Depends(get_current_user)
) -> dict:
    """Update finding status (open, remediated, accepted, false_positive)."""
    new_status = body.status
    store = get_store()
    # Resolve + authorize before mutating, so a scoped user cannot flip the
    # status of another client's finding by guessing its ID.
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found for status update: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    if not store.update_finding_status(finding_id, new_status):
        raise not_found("Finding", finding_id)
    logger.info("Finding status updated: id=%s status=%s", finding_id, new_status)
    return {"id": finding_id, "status": new_status}
