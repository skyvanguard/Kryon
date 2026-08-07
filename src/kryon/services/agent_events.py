"""Rich agent-turn event protocol — the single contract between the full Kryon
turn pipeline and every front-end that renders it.

One turn of the REPL produces a *stream* of things: the deterministic engine
phase runs, pre_hooks fire, the model thinks, calls tools, findings land, it
narrates, the reflective loop injects reflections, and finally it closes with a
report. Today that stream is rendered inline in ``cli/_original.py`` with direct
Rich prints — so only the in-process console can consume it. A Go/Charm TUI (or
the SSE server, or a web client) has nothing structured to render.

This module defines the structured event each of those moments emits. The turn
pipeline emits ``AgentEvent``s to an ``EventSink``; the sink decides how to
render them:

- ``ConsoleSink`` (step 2) → Rich prints, exactly like the REPL today.
- ``SSESink`` (step 2) → ``event:``/``data:`` frames for ``GET /runs/{id}/stream``.
- a future Go/Charm TUI → parses the same JSON off the SSE stream.

The event is trivially JSON-serialisable (for SSE / the Go client) *and*
consumable in-process (for the Rich REPL), so one pipeline drives all three
front-ends with no divergence.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class EventKind:
    """Canonical event-kind tags. String constants (not an Enum) so they
    serialise as-is over JSON and read cleanly on the wire for the Go client."""

    TURN_START = "turn_start"
    ENGINE_PHASE = "engine_phase"  # deterministic orchestrator/engine ran
    PRE_HOOK = "pre_hook"  # a skill pre_hook fired
    THINKING = "thinking"  # reasoning delta/block (thinking models)
    TOOL_STARTED = "tool_started"  # a tool invocation began
    TOOL_OUTPUT = "tool_output"  # a tool invocation finished
    FINDING = "finding"  # a security finding landed
    ASSISTANT = "assistant"  # the model's narrative text (markdown)
    REFLECTION = "reflection"  # the reflective loop injected a reflection
    TURN_END = "turn_end"
    DONE = "done"  # engagement closed + final report
    ERROR = "error"

    ALL: frozenset[str] = frozenset(
        {
            TURN_START,
            ENGINE_PHASE,
            PRE_HOOK,
            THINKING,
            TOOL_STARTED,
            TOOL_OUTPUT,
            FINDING,
            ASSISTANT,
            REFLECTION,
            TURN_END,
            DONE,
            ERROR,
        }
    )


@dataclass(frozen=True)
class AgentEvent:
    """One structured event in a turn's stream.

    ``kind`` is an ``EventKind`` tag; ``payload`` carries kind-specific fields
    (already JSON-safe); ``seq`` is a monotonic ordering index assigned by the
    sink (0 until then), so a reconnecting client can resume/dedup deterministically.
    """

    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    seq: int = 0

    def with_seq(self, seq: int) -> AgentEvent:
        """Return a copy stamped with an ordering index (frozen → new instance)."""
        return AgentEvent(kind=self.kind, payload=self.payload, seq=seq)

    def to_dict(self) -> dict[str, Any]:
        """Flat JSON object: ``{kind, seq, **payload}`` — one shape for SSE and
        the Go client. payload keys never collide with kind/seq (guarded by the
        factory helpers below)."""
        return {"kind": self.kind, "seq": self.seq, **self.payload}

    def to_sse(self) -> str:
        """A Server-Sent-Events frame. ``event:`` lets EventSource clients (and
        the Go TUI) filter by kind without parsing the body first."""
        body = json.dumps(self.to_dict(), ensure_ascii=False)
        return f"event: {self.kind}\ndata: {body}\n\n"


# --------------------------------------------------------------------------- #
# Factory helpers — type-safe construction. Prefer these over AgentEvent(...)  #
# directly so payload shapes stay consistent across producers.                #
# --------------------------------------------------------------------------- #


def turn_start(turn_index: int) -> AgentEvent:
    return AgentEvent(EventKind.TURN_START, {"turn_index": turn_index})


def engine_phase(note: str, findings_count: int = 0) -> AgentEvent:
    """The deterministic engine/orchestrator ran (discovery → battery → compliance)."""
    return AgentEvent(EventKind.ENGINE_PHASE, {"note": note, "findings_count": findings_count})


def pre_hook(name: str) -> AgentEvent:
    """A skill pre_hook fired before the LLM took control."""
    return AgentEvent(EventKind.PRE_HOOK, {"name": name})


def thinking(text: str) -> AgentEvent:
    return AgentEvent(EventKind.THINKING, {"text": text})


def tool_started(tool: str, args_summary: str = "", step_id: int | None = None) -> AgentEvent:
    return AgentEvent(EventKind.TOOL_STARTED, {"tool": tool, "args_summary": args_summary, "step_id": step_id})


def tool_output(
    tool: str,
    *,
    status: str = "ok",
    duration_s: float = 0.0,
    summary: str = "",
    output: str = "",
    step_id: int | None = None,
    collapsed: bool = False,
) -> AgentEvent:
    """A tool finished. The output flows on the wire (bounded by the caller) so a
    front-end can PREVIEW it live — seeing the command's result is what makes the
    TUI feel like a real terminal. ``collapsed`` just flags that there's more than
    fits inline, so the renderer can show a preview + a /show hint."""
    return AgentEvent(
        EventKind.TOOL_OUTPUT,
        {
            "tool": tool,
            "status": status,
            "duration_s": round(duration_s, 3),
            "summary": summary,
            "output": output,
            "step_id": step_id,
            "collapsed": collapsed,
        },
    )


def finding(
    severity: str,
    detail: str,
    *,
    cwe: str = "",
    location: str = "",
    verified: bool = False,
) -> AgentEvent:
    return AgentEvent(
        EventKind.FINDING,
        {
            "severity": (severity or "INFO").upper(),
            "detail": detail,
            "cwe": cwe,
            "location": location,
            "verified": verified,
        },
    )


def assistant(markdown: str) -> AgentEvent:
    """The model's narrative for the turn (rendered as markdown by every front-end)."""
    return AgentEvent(EventKind.ASSISTANT, {"markdown": markdown})


def reflection(note: str) -> AgentEvent:
    """The reflective loop injected a self-critique / next-action nudge."""
    return AgentEvent(EventKind.REFLECTION, {"note": note})


def turn_end(turn_index: int) -> AgentEvent:
    return AgentEvent(EventKind.TURN_END, {"turn_index": turn_index})


def done(report_markdown: str = "", findings_count: int = 0) -> AgentEvent:
    return AgentEvent(EventKind.DONE, {"report_markdown": report_markdown, "findings_count": findings_count})


def error(message: str) -> AgentEvent:
    return AgentEvent(EventKind.ERROR, {"message": message})


# --------------------------------------------------------------------------- #
# Sinks                                                                         #
# --------------------------------------------------------------------------- #


@runtime_checkable
class EventSink(Protocol):
    """Anything that can receive turn events. Implementations: ConsoleSink
    (Rich REPL), SSESink (server stream), CollectingSink (tests)."""

    def emit(self, event: AgentEvent) -> None: ...


class SequencingSink:
    """Base sink that stamps a monotonic ``seq`` on every event before handing
    it to ``_emit``. Subclasses override ``_emit`` with the actual rendering;
    they get ordering for free. NOT a Protocol impl by itself — ``_emit`` is
    abstract-by-convention (raises)."""

    def __init__(self) -> None:
        self._seq = 0

    def emit(self, event: AgentEvent) -> None:
        stamped = event.with_seq(self._seq)
        self._seq += 1
        self._emit(stamped)

    def _emit(self, event: AgentEvent) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class CollectingSink(SequencingSink):
    """Buffers events in a list. For tests and for the SSE endpoint's replay
    buffer (a late-connecting client can be caught up from ``events``)."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[AgentEvent] = []

    def _emit(self, event: AgentEvent) -> None:
        self.events.append(event)

    def kinds(self) -> list[str]:
        """Ordered list of event kinds — handy for asserting a turn's shape."""
        return [e.kind for e in self.events]


class CallbackSink(SequencingSink):
    """Sink that calls a function on each (sequenced) event. Generic glue — the
    server uses it to push SSE frames onto a run's existing event buffer
    (``CallbackSink(lambda e: run.events.append({"sse": e.to_sse()}))``) so the
    current ``/runs/{id}/stream`` poller works unchanged. Best-effort: a raising
    callback never breaks the turn."""

    def __init__(self, fn: Any) -> None:
        super().__init__()
        self._fn = fn

    def _emit(self, event: AgentEvent) -> None:
        try:
            self._fn(event)
        except Exception:  # noqa: BLE001 — emission must never break the turn
            pass


class SSESink(SequencingSink):
    """Bridges the (sync-emit) turn pipeline to an async Server-Sent-Events
    generator. The turn runs (in a task) and ``emit()``s events into a buffer;
    the ``/runs/{id}/stream`` endpoint awaits ``stream()`` and yields SSE frames.

    Uses the same poll-a-buffer pattern the existing server stream uses (rather
    than an asyncio.Queue, which binds to a specific loop at construction) — so
    the sink can be created outside a running loop and drained by whichever
    request handler streams it. ``stream()`` terminates once ``TURN_END`` lands
    (or ``close()`` is called), so a client never hangs waiting past the turn.
    """

    def __init__(self) -> None:
        super().__init__()
        self.events: list[AgentEvent] = []
        self._closed = False

    def _emit(self, event: AgentEvent) -> None:
        self.events.append(event)
        if event.kind == EventKind.TURN_END:
            self._closed = True

    def close(self) -> None:
        """Force the stream to terminate even if no TURN_END was emitted
        (e.g. the turn task was cancelled)."""
        self._closed = True

    async def stream(self, poll_interval: float = 0.05) -> AsyncIterator[str]:
        """Yield SSE frames as events arrive, ending when the turn closes."""
        idx = 0
        while True:
            while idx < len(self.events):
                yield self.events[idx].to_sse()
                idx += 1
            if self._closed:
                break
            await asyncio.sleep(poll_interval)


__all__ = [
    "AgentEvent",
    "CallbackSink",
    "CollectingSink",
    "EventKind",
    "EventSink",
    "SSESink",
    "SequencingSink",
    "assistant",
    "done",
    "engine_phase",
    "error",
    "finding",
    "pre_hook",
    "reflection",
    "thinking",
    "tool_output",
    "tool_started",
    "turn_end",
    "turn_start",
]
