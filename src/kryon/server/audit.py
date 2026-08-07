"""Audit logging — records security-relevant actions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from kryon.server.logging_config import get_logger
from kryon.server.middleware.request_id import get_request_id

logger = get_logger(__name__)


def log_action(
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    user_id: str | None = None,
    username: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Write an audit log entry to the database."""
    entry = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "username": username,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
        "ip_address": ip_address,
        "request_id": get_request_id(),
    }

    try:
        from kryon.server.deps import get_store

        store = get_store()
        store.write_audit_log(entry)
    except Exception:
        logger.warning("Failed to write audit log: %s", entry, exc_info=True)
