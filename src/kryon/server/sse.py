"""SSE streaming utilities — shared by all endpoints that use Server-Sent Events."""

from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi.responses import StreamingResponse

SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


def sse_response(generator: AsyncGenerator) -> StreamingResponse:
    """Wrap an async generator in a StreamingResponse with SSE headers."""
    return StreamingResponse(generator, media_type="text/event-stream", headers=SSE_HEADERS)


def sse_event(event: str, data: dict) -> str:
    """Format a single SSE event string."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
