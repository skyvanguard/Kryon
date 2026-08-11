"""Per-task bridge so the model layer can emit ``thinking`` events to the
active turn's ``EventSink`` without threading it through the whole SDK call
stack.

The problem mirrors FASE 6 (``intelligence.planner_runtime``): the model's
reasoning is extracted deep inside ``models.openai_native._fetch_response`` —
per LLM response — but the ``EventSink`` (SSE stream / Charm TUI) lives up in
``run_with_reflection``. The SDK call layers in between have no reference to it.
This module bridges the gap with a ``contextvars.ContextVar`` set by the
reflective runner around a run and read by the model layer.

Why ContextVar and not a module-level global: the async loop may interleave
coroutines across runs in the same process; a global would mix state across
runs, whereas ``ContextVar`` is per-task by design (and a child task — the
model call — inherits the parent's snapshot, which is exactly the read
direction we need).

Banca-safe: no I/O, no network, no LLM calls. Emission is best-effort and can
never break a turn (a raising sink is swallowed). When no sink is set (the REPL
/ ``kryon investigate`` / engage paths render inline), every accessor is a
no-op — so the change is invisible to those front-ends.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# Longest reasoning block streamed as a single ``thinking`` event. A local
# reasoning model (qwen-unc) can emit ~15K chars of chain-of-thought per turn;
# streaming the whole thing floods the log, so cap generously and mark the
# elision. Matches the tool-output/​fact slice sizes used elsewhere.
_THINKING_MAX_CHARS = 8000

# ``None`` means "no run is currently streaming to a sink" — every accessor
# then no-ops, so the REPL / engage / investigate inline-render paths are
# byte-for-byte unchanged.
_current_sink: ContextVar[Any | None] = ContextVar("kryon_event_sink", default=None)


def set_event_sink(sink: Any) -> None:
    """Bind the active turn's ``EventSink`` to this task. Called by
    ``run_with_reflection`` around a run when a front-end subscribed
    (``event_sink is not None``); ``None`` clears it."""
    _current_sink.set(sink)


def clear_event_sink() -> None:
    """Release the per-task sink so a leaked ContextVar doesn't feed a later
    run in the same task. Called by ``run_with_reflection`` on every exit path,
    next to ``clear_current_state`` (planner_runtime)."""
    _current_sink.set(None)


def get_event_sink() -> Any | None:
    """Read the per-task sink. ``None`` when no reflective run is streaming."""
    return _current_sink.get()


def emit_thinking(text: str, *, max_chars: int = _THINKING_MAX_CHARS) -> None:
    """Best-effort: emit a ``thinking`` AgentEvent to the active sink.

    No-op when no sink is set (inline-render front-ends / tests) or the text is
    empty. Bounds the payload to ``max_chars`` (with an elision marker) so a
    verbose reasoning model can't flood a single SSE frame. Never raises — event
    delivery must never break the agent turn.
    """
    sink = _current_sink.get()
    if sink is None:
        return
    body = (text or "").strip()
    if not body:
        return
    if len(body) > max_chars:
        body = body[:max_chars] + "…"
    try:
        from kryon.services.agent_events import thinking

        sink.emit(thinking(body))
    except Exception:  # noqa: BLE001 — emission must never break the turn
        pass


__all__ = [
    "set_event_sink",
    "clear_event_sink",
    "get_event_sink",
    "emit_thinking",
]
