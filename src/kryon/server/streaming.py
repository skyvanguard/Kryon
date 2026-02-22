"""SSE serialization for StreamEvent objects."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents.stream_events import (
    AgentUpdatedStreamEvent,
    RawResponsesStreamEvent,
    RunItemStreamEvent,
    StreamEvent,
)


def _serialize_run_item(item: Any) -> dict[str, Any]:
    """Serialize a RunItem to a JSON-friendly dict."""
    data: dict[str, Any] = {"type": type(item).__name__}
    if hasattr(item, "agent") and hasattr(item.agent, "name"):
        data["agent"] = item.agent.name
    if hasattr(item, "raw_item"):
        raw = item.raw_item
        if isinstance(raw, dict):
            data["raw"] = raw
        elif hasattr(raw, "model_dump"):
            data["raw"] = raw.model_dump(mode="json", exclude_none=True)
        else:
            data["raw"] = str(raw)
    return data


def stream_event_to_sse(event: StreamEvent) -> str:
    """Convert a StreamEvent into an SSE-formatted string."""
    if isinstance(event, RunItemStreamEvent):
        payload = {
            "name": event.name,
            "item": _serialize_run_item(event.item),
        }
        return f"event: {event.name}\ndata: {json.dumps(payload, default=str)}\n\n"

    if isinstance(event, AgentUpdatedStreamEvent):
        payload = {
            "agent": event.new_agent.name,
        }
        return f"event: agent_updated\ndata: {json.dumps(payload)}\n\n"

    if isinstance(event, RawResponsesStreamEvent):
        # Skip raw LLM events to reduce noise; clients use higher-level events
        return ""

    return ""


def done_event(output: str = "") -> str:
    """Return a final SSE event signaling the run is complete."""
    return f"event: done\ndata: {json.dumps({'output': output})}\n\n"


def error_event(message: str) -> str:
    """Return an SSE event signaling an error."""
    return f"event: error\ndata: {json.dumps({'error': message})}\n\n"
