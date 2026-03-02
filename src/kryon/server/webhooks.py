"""Webhook notification delivery with retry and exponential backoff."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)


async def _retry_post(
    url: str,
    payload: dict,
    headers: dict | None = None,
    max_attempts: int = 3,
    timeout: int = 10,
) -> bool:
    """POST with exponential backoff. Delays: 1s, 4s, 16s (+ jitter 0-30%).

    Returns True if any attempt succeeds.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload, headers=headers or {})
                resp.raise_for_status()
                logger.info(
                    "POST delivered to %s (attempt %d/%d)", url, attempt, max_attempts
                )
                return True
        except Exception:
            if attempt < max_attempts:
                base_delay = 4 ** (attempt - 1)  # 1, 4, 16
                jitter = base_delay * random.uniform(0, 0.3)
                delay = base_delay + jitter
                logger.warning(
                    "POST to %s failed (attempt %d/%d), retrying in %.1fs",
                    url,
                    attempt,
                    max_attempts,
                    delay,
                    exc_info=True,
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "POST to %s failed after %d attempts", url, max_attempts, exc_info=True
                )
    return False


async def send_webhook(url: str, event: str, data: dict) -> bool:
    """Send a webhook notification with retry. Returns True if successful."""
    payload = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    return await _retry_post(url, payload)
