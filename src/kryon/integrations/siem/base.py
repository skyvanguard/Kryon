"""Base class for SIEM forwarders."""

from __future__ import annotations

import abc
from typing import Any

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem_secret import decrypt_token


class BaseSIEMForwarder(abc.ABC):
    """Abstract base for SIEM event forwarders."""

    def __init__(self, config: dict[str, Any]):
        self._config = config
        self.name = config.get("name", "unknown")
        self.endpoint = config.get("endpoint", "")
        self.token = decrypt_token(config.get("token", ""))
        self.index_name = config.get("index_name", "")
        self.extra = config.get("config_json", {})
        if isinstance(self.extra, str):
            import json

            try:
                self.extra = json.loads(self.extra)
            except (json.JSONDecodeError, ValueError):
                self.extra = {}

    @abc.abstractmethod
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send a single event. Returns True on success."""

    async def send_batch(self, events: list[SIEMEvent]) -> int:
        """Send multiple events. Returns count of successfully sent. Default: send one by one."""
        success = 0
        for event in events:
            try:
                if await self.send_event(event):
                    success += 1
            except Exception:
                pass
        return success

    def should_forward(self, event: SIEMEvent) -> bool:
        """Filter events. Override to implement severity/type filtering."""
        min_severity = self.extra.get("min_severity")
        if min_severity:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            event_level = severity_order.get(event.severity, 4)
            min_level = severity_order.get(min_severity, 4)
            return event_level <= min_level
        return True

    def format_event(self, event: SIEMEvent) -> dict:
        """Convert SIEMEvent to dict for serialization."""
        return event.model_dump()
