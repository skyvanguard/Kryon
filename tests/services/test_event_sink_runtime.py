"""Per-task EventSink bridge — lets the model layer emit `thinking` events to
the active turn's sink without threading it through the SDK call stack. Mirrors
the ContextVar-per-task rationale of intelligence.planner_runtime."""

from __future__ import annotations

from kryon.services import event_sink_runtime as esr
from kryon.services.agent_events import CollectingSink, EventKind


def test_get_default_is_none():
    esr.clear_event_sink()
    assert esr.get_event_sink() is None


def test_set_then_get_roundtrips():
    sink = CollectingSink()
    esr.set_event_sink(sink)
    try:
        assert esr.get_event_sink() is sink
    finally:
        esr.clear_event_sink()
    assert esr.get_event_sink() is None


def test_emit_thinking_noop_without_sink():
    esr.clear_event_sink()
    # No sink bound → must not raise and must produce nothing.
    esr.emit_thinking("razonando sobre el target")  # no assertion target, just no crash


def test_emit_thinking_emits_to_bound_sink():
    sink = CollectingSink()
    esr.set_event_sink(sink)
    try:
        esr.emit_thinking("el puerto 8009 es AJP — probar Ghostcat")
    finally:
        esr.clear_event_sink()

    assert sink.kinds() == [EventKind.THINKING]
    assert sink.events[0].payload["text"] == "el puerto 8009 es AJP — probar Ghostcat"


def test_emit_thinking_skips_empty_and_whitespace():
    sink = CollectingSink()
    esr.set_event_sink(sink)
    try:
        esr.emit_thinking("")
        esr.emit_thinking("   \n\t ")
        esr.emit_thinking(None)  # type: ignore[arg-type]
    finally:
        esr.clear_event_sink()
    assert sink.events == []


def test_emit_thinking_truncates_long_reasoning():
    sink = CollectingSink()
    esr.set_event_sink(sink)
    try:
        esr.emit_thinking("x" * 5000, max_chars=100)
    finally:
        esr.clear_event_sink()
    text = sink.events[0].payload["text"]
    assert len(text) == 101  # 100 chars + the elision marker
    assert text.endswith("…")


def test_emit_thinking_swallows_raising_sink():
    class _BoomSink:
        def emit(self, event):  # noqa: ANN001
            raise RuntimeError("sink is down")

    esr.set_event_sink(_BoomSink())
    try:
        # Emission must never propagate a sink failure into the model call.
        esr.emit_thinking("esto no debe romper el turno")
    finally:
        esr.clear_event_sink()
