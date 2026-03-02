"""Splunk HTTP Event Collector (HEC) forwarder."""

from __future__ import annotations

import json
import logging

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.base import BaseSIEMForwarder

logger = logging.getLogger(__name__)


class SplunkHECForwarder(BaseSIEMForwarder):
    """Forward events to Splunk via HEC JSON endpoint."""

    async def send_event(self, event: SIEMEvent) -> bool:
        import httpx

        payload = {
            "time": event.timestamp,
            "source": event.source,
            "sourcetype": f"kryon:{event.event_type}",
            "index": self.index_name or "main",
            "event": self.format_event(event),
        }

        async with httpx.AsyncClient(verify=self.extra.get("verify_ssl", False), timeout=10.0) as client:
            resp = await client.post(
                f"{self.endpoint}/services/collector",
                headers={"Authorization": f"Splunk {self.token}"},
                json=payload,
            )
            if resp.status_code == 200:
                return True
            logger.warning("Splunk HEC returned %d: %s", resp.status_code, resp.text)
            return False

    async def send_batch(self, events: list[SIEMEvent]) -> int:
        import httpx

        lines = []
        for event in events:
            payload = {
                "time": event.timestamp,
                "source": event.source,
                "sourcetype": f"kryon:{event.event_type}",
                "index": self.index_name or "main",
                "event": self.format_event(event),
            }
            lines.append(json.dumps(payload))

        body = "\n".join(lines)
        async with httpx.AsyncClient(verify=self.extra.get("verify_ssl", False), timeout=30.0) as client:
            resp = await client.post(
                f"{self.endpoint}/services/collector",
                headers={"Authorization": f"Splunk {self.token}"},
                content=body,
            )
            if resp.status_code == 200:
                return len(events)
            logger.warning("Splunk batch HEC returned %d", resp.status_code)
            return 0
