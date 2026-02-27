"""QRadar LEEF forwarder."""

from __future__ import annotations

import logging

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.base import BaseSIEMForwarder

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}


class QRadarLEEFForwarder(BaseSIEMForwarder):
    """Forward events to QRadar via LEEF 2.0 format over HTTP."""

    def to_leef(self, event: SIEMEvent) -> str:
        """Convert event to LEEF 2.0 format string."""
        sev = _SEVERITY_MAP.get(event.severity, 1)
        attrs = [
            f"severity={sev}",
            f"title={event.title}",
            f"description={event.description}",
            f"eventType={event.event_type}",
            f"source={event.source}",
        ]
        if event.client_id:
            attrs.append(f"clientId={event.client_id}")
        if event.user:
            attrs.append(f"user={event.user}")
        for k, v in event.metadata.items():
            attrs.append(f"{k}={v}")

        attr_str = "\t".join(attrs)
        return f"LEEF:2.0|Kryon|KRYON|1.0.0|{event.event_type}|{attr_str}"

    async def send_event(self, event: SIEMEvent) -> bool:
        import httpx

        leef_msg = self.to_leef(event)

        async with httpx.AsyncClient(verify=self.extra.get("verify_ssl", False), timeout=10.0) as client:
            resp = await client.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "text/plain"},
                content=leef_msg,
            )
            if resp.status_code in (200, 201, 202):
                return True
            logger.warning("QRadar returned %d: %s", resp.status_code, resp.text)
            return False
