"""Notification routing rules — evaluate events and route to channels."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

# Known event types
EVENT_TYPES = [
    "new_critical_finding",
    "sla_overdue",
    "scan_complete",
    "engagement_complete",
    "system_health_degraded",
    "license_expiring",
]

# Severity levels for filtering
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


def evaluate_rules(
    rules: list[dict],
    channels: list[dict],
    event_type: str,
    severity: str = "",
    client_id: str = "",
) -> list[dict]:
    """Evaluate notification rules and return matching channels with their configs.

    Args:
        rules: List of rule dicts from DB (with event_type, severity_filter, client_filter, channel_ids, enabled).
        channels: List of channel dicts from DB (with id, channel_type, config_json, enabled).
        event_type: The event being triggered.
        severity: Severity of the event (optional).
        client_id: Client associated with the event (optional).

    Returns:
        List of matching channel dicts that should receive the notification.
    """
    matching_channel_ids: set[str] = set()

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        # Match event type
        if rule.get("event_type") != event_type:
            continue

        # Match severity filter (comma-separated or empty = all)
        sev_filter = rule.get("severity_filter", "")
        if sev_filter and severity:
            allowed_sevs = [s.strip().lower() for s in sev_filter.split(",")]
            if severity.lower() not in allowed_sevs:
                continue

        # Match client filter (comma-separated or empty = all)
        client_filter = rule.get("client_filter", "")
        if client_filter and client_id:
            allowed_clients = [c.strip() for c in client_filter.split(",")]
            if client_id not in allowed_clients:
                continue

        # Collect channel IDs from this rule
        channel_ids_raw = rule.get("channel_ids", "[]")
        if isinstance(channel_ids_raw, str):
            try:
                channel_ids = json.loads(channel_ids_raw)
            except (json.JSONDecodeError, TypeError):
                channel_ids = []
        else:
            channel_ids = channel_ids_raw

        for cid in channel_ids:
            matching_channel_ids.add(cid)

    # Resolve channel IDs to actual channel configs
    matched_channels = []
    channel_map = {ch["id"]: ch for ch in channels if ch.get("enabled", True)}
    for cid in matching_channel_ids:
        if cid in channel_map:
            matched_channels.append(channel_map[cid])

    return matched_channels
