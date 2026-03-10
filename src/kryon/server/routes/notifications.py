"""Notification channels, rules, and log API routes."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, model_validator

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["notifications"], dependencies=[Depends(require_api_key)])


# --- Models ---


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    channel_type: str = Field(..., pattern=r"^(email|slack|teams|pagerduty|webhook)$")
    config_json: dict = Field(default_factory=dict)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_config_size(self):
        if len(json.dumps(self.config_json)) > 10_000:
            raise ValueError("config_json too large (max 10KB)")
        return self


class ChannelUpdate(BaseModel):
    name: str | None = None
    config_json: dict | None = None
    enabled: bool | None = None


class RuleCreate(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=100)
    severity_filter: str = Field("", max_length=100)
    client_filter: str = Field("", max_length=100)
    channel_ids: list[str] = Field(default=[], max_length=50)
    digest_mode: str = Field("immediate", pattern=r"^(immediate|hourly|daily)$")
    enabled: bool = True


# --- Channel endpoints ---


@router.post("/notifications/channels")
async def create_channel(body: ChannelCreate) -> dict:
    """Create a notification channel."""
    store = get_store()
    channel_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    store.save_notification_channel(
        channel_id=channel_id,
        name=body.name,
        channel_type=body.channel_type,
        config_json=json.dumps(body.config_json),
        enabled=body.enabled,
        created_at=now,
    )
    logger.info("Notification channel created: id=%s type=%s", channel_id, body.channel_type)
    return {"id": channel_id, "name": body.name, "channel_type": body.channel_type}


@router.get("/notifications/channels")
async def list_channels() -> list[dict]:
    """List all notification channels."""
    store = get_store()
    return store.list_notification_channels()


@router.put("/notifications/channels/{channel_id}")
async def update_channel(channel_id: str, body: ChannelUpdate) -> dict:
    """Update a notification channel."""
    store = get_store()
    existing = store.get_notification_channel(channel_id)
    if not existing:
        logger.warning("Notification channel not found: %s", channel_id)
        raise not_found("NotificationChannel", channel_id)
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.config_json is not None:
        updates["config_json"] = json.dumps(body.config_json)
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if updates:
        store.update_notification_channel(channel_id, **updates)
        logger.info("Notification channel updated: %s", channel_id)
    return store.get_notification_channel(channel_id)


@router.delete("/notifications/channels/{channel_id}")
async def delete_channel(channel_id: str) -> dict:
    """Delete a notification channel."""
    store = get_store()
    if not store.delete_notification_channel(channel_id):
        logger.warning("Notification channel not found for delete: %s", channel_id)
        raise not_found("NotificationChannel", channel_id)
    logger.info("Notification channel deleted: %s", channel_id)
    return {"deleted": True, "id": channel_id}


# --- Rule endpoints ---


@router.post("/notifications/rules")
async def create_rule(body: RuleCreate) -> dict:
    """Create a notification rule."""
    store = get_store()
    rule_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    store.save_notification_rule(
        rule_id=rule_id,
        event_type=body.event_type,
        severity_filter=body.severity_filter,
        client_filter=body.client_filter,
        channel_ids=json.dumps(body.channel_ids),
        digest_mode=body.digest_mode,
        enabled=body.enabled,
        created_at=now,
    )
    logger.info("Notification rule created: id=%s event=%s", rule_id, body.event_type)
    return {"id": rule_id, "event_type": body.event_type}


@router.get("/notifications/rules")
async def list_rules() -> list[dict]:
    """List all notification rules."""
    store = get_store()
    return store.list_notification_rules()


@router.delete("/notifications/rules/{rule_id}")
async def delete_rule(rule_id: str) -> dict:
    """Delete a notification rule."""
    store = get_store()
    if not store.delete_notification_rule(rule_id):
        logger.warning("Notification rule not found for delete: %s", rule_id)
        raise not_found("NotificationRule", rule_id)
    logger.info("Notification rule deleted: %s", rule_id)
    return {"deleted": True, "id": rule_id}


# --- Log + Test ---


@router.get("/notifications/log")
async def get_notification_log(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    """Get notification delivery log."""
    store = get_store()
    items = store.list_notification_log(offset=offset, limit=limit)
    return {"items": items, "offset": offset, "limit": limit}


@router.post("/notifications/test/{channel_id}")
async def test_channel(channel_id: str) -> dict:
    """Send a test notification to a channel."""
    store = get_store()
    ch = store.get_notification_channel(channel_id)
    if not ch:
        logger.warning("Notification channel not found for test: %s", channel_id)
        raise not_found("NotificationChannel", channel_id)

    from kryon.notifications.channels import get_channel

    config = (
        json.loads(ch.get("config_json", "{}")) if isinstance(ch.get("config_json"), str) else ch.get("config_json", {})
    )
    channel = get_channel(ch["channel_type"], config)
    success = await channel.send(
        subject="Test Notification",
        body="This is a test notification from KRYON Security Platform.",
        payload={"severity": "info", "event_type": "test"},
    )

    # Log the attempt
    log_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    store.log_notification(
        log_id=log_id,
        channel_id=channel_id,
        event_type="test",
        payload_json=json.dumps({"test": True}),
        sent_at=now,
        success=success,
        error_message="" if success else "Test delivery failed",
    )

    logger.info("Test notification sent: channel=%s success=%s", channel_id, success)
    return {"success": success, "channel_id": channel_id}
