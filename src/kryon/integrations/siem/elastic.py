"""Elastic SIEM forwarder using ECS (Elastic Common Schema)."""

from __future__ import annotations

import logging
from typing import Any

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.base import BaseSIEMForwarder

logger = logging.getLogger(__name__)

_SEVERITY_TO_ECS = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}

_EVENT_TYPE_TO_CATEGORY = {
    "finding": ["threat"],
    "scan_start": ["process"],
    "scan_complete": ["process"],
    "auth": ["authentication"],
    "audit": ["configuration"],
}


class ElasticSIEMForwarder(BaseSIEMForwarder):
    """Forward events to Elastic using ECS format."""

    def to_ecs(self, event: SIEMEvent) -> dict[str, Any]:
        """Convert SIEMEvent to Elastic Common Schema document."""
        return {
            "@timestamp": event.timestamp,
            "event": {
                "kind": "alert" if event.event_type == "finding" else "event",
                "category": _EVENT_TYPE_TO_CATEGORY.get(event.event_type, ["process"]),
                "severity": _SEVERITY_TO_ECS.get(event.severity, 5),
                "action": event.event_type,
            },
            "message": event.title,
            "observer": {
                "name": "kryon",
                "type": "security-platform",
                "vendor": "Kryon Security",
            },
            "kryon": {
                "description": event.description,
                "client_id": event.client_id,
                "user": event.user,
                **event.metadata,
            },
        }

    async def send_event(self, event: SIEMEvent) -> bool:
        import httpx

        doc = self.to_ecs(event)
        index = self.index_name or "kryon-events"

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"ApiKey {self.token}"

        async with httpx.AsyncClient(verify=self.extra.get("verify_ssl", False), timeout=10.0) as client:
            resp = await client.post(
                f"{self.endpoint}/{index}/_doc",
                headers=headers,
                json=doc,
            )
            if resp.status_code in (200, 201):
                return True
            logger.warning("Elastic returned %d: %s", resp.status_code, resp.text)
            return False

    async def send_batch(self, events: list[SIEMEvent]) -> int:
        import httpx

        index = self.index_name or "kryon-events"
        lines = []
        for event in events:
            lines.append(f'{{"index": {{"_index": "{index}"}}}}')
            import json

            lines.append(json.dumps(self.to_ecs(event)))

        body = "\n".join(lines) + "\n"
        headers = {"Content-Type": "application/x-ndjson"}
        if self.token:
            headers["Authorization"] = f"ApiKey {self.token}"

        async with httpx.AsyncClient(verify=self.extra.get("verify_ssl", False), timeout=30.0) as client:
            resp = await client.post(
                f"{self.endpoint}/_bulk",
                headers=headers,
                content=body,
            )
            if resp.status_code == 200:
                return len(events)
            logger.warning("Elastic bulk returned %d", resp.status_code)
            return 0
