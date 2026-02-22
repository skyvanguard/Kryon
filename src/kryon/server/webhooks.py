"""Webhook notification delivery."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


async def send_webhook(url: str, event: str, data: dict) -> bool:
    """Send a webhook notification. Returns True if successful."""
    payload = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            logger.info("Webhook delivered to %s: %s", url, event)
            return True
    except Exception:
        logger.warning("Webhook delivery failed to %s", url, exc_info=True)
        return False
