"""Notification digest aggregator — batches events for hourly/daily digests."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class DigestAggregator:
    """Accumulates notification events and flushes by digest mode."""

    def __init__(self):
        # key = (channel_id, digest_mode), value = list of pending events
        self._pending: dict[tuple[str, str], list[dict]] = defaultdict(list)

    def add_event(self, channel_id: str, digest_mode: str, event: dict) -> bool:
        """Add an event to the digest queue.

        Returns True if the event should be sent immediately (digest_mode='immediate').
        Returns False if the event was queued for later delivery.
        """
        if digest_mode == "immediate":
            return True

        key = (channel_id, digest_mode)
        self._pending[key].append(
            {
                **event,
                "queued_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.debug("Queued event for %s digest: channel=%s", digest_mode, channel_id)
        return False

    def flush(self, digest_mode: str) -> dict[str, list[dict]]:
        """Flush all pending events for a given digest mode.

        Args:
            digest_mode: 'hourly' or 'daily'

        Returns:
            Dict mapping channel_id to list of events to send.
        """
        result: dict[str, list[dict]] = {}
        keys_to_remove = []

        for key, events in self._pending.items():
            channel_id, mode = key
            if mode == digest_mode and events:
                result[channel_id] = list(events)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._pending[key]

        if result:
            total = sum(len(v) for v in result.values())
            logger.info("Flushed %d events for %s digest across %d channels", total, digest_mode, len(result))

        return result

    def pending_count(self, digest_mode: str | None = None) -> int:
        """Count pending events, optionally filtered by digest mode."""
        count = 0
        for (_, mode), events in self._pending.items():
            if digest_mode is None or mode == digest_mode:
                count += len(events)
        return count

    def clear(self) -> None:
        """Clear all pending events."""
        self._pending.clear()
