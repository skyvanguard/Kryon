"""Agent-turn event protocol — the contract every front-end (Rich REPL, SSE
server, future Go/Charm TUI) renders. These lock the wire shape so the Go client
can be written against a stable JSON schema."""

from __future__ import annotations

import asyncio
import json

from kryon.services import agent_events as ev


def test_factory_kinds_are_all_registered():
    # Every factory helper must produce a kind that's in EventKind.ALL, or a
    # client filtering by known kinds would silently drop it.
    produced = {
        ev.turn_start(0).kind,
        ev.engine_phase("x").kind,
        ev.pre_hook("h").kind,
        ev.thinking("t").kind,
        ev.tool_started("nmap").kind,
        ev.tool_output("nmap").kind,
        ev.finding("HIGH", "d").kind,
        ev.assistant("md").kind,
        ev.reflection("r").kind,
        ev.turn_end(0).kind,
        ev.done().kind,
        ev.error("boom").kind,
    }
    assert produced == ev.EventKind.ALL


def test_to_dict_is_flat_kind_seq_payload():
    e = ev.tool_started("nmap", "10.0.0.1 -sV", step_id=3).with_seq(7)
    d = e.to_dict()
    assert d == {
        "kind": "tool_started",
        "seq": 7,
        "tool": "nmap",
        "args_summary": "10.0.0.1 -sV",
        "step_id": 3,
    }


def test_to_sse_frame_shape():
    frame = ev.finding("high", "SPF missing", cwe="CWE-1390").with_seq(2).to_sse()
    assert frame.startswith("event: finding\ndata: ")
    assert frame.endswith("\n\n")
    body = json.loads(frame.split("data: ", 1)[1].strip())
    assert body["kind"] == "finding"
    assert body["seq"] == 2
    assert body["severity"] == "HIGH"  # normalised upper-case
    assert body["cwe"] == "CWE-1390"


def test_finding_severity_normalised_and_defaulted():
    assert ev.finding("critical", "x").payload["severity"] == "CRITICAL"
    assert ev.finding("", "x").payload["severity"] == "INFO"


def test_tool_output_keeps_body_and_flags_collapsed():
    big = "line\n" * 500
    collapsed = ev.tool_output("run_command", summary="500 lines", output=big, step_id=5, collapsed=True)
    # Body flows on the wire (bounded by the caller) so the front-end can preview it.
    assert collapsed.payload["output"] == big
    assert collapsed.payload["summary"] == "500 lines"
    assert collapsed.payload["collapsed"] is True
    inline = ev.tool_output("run_command", output="short", collapsed=False)
    assert inline.payload["output"] == "short"


def test_tool_output_duration_rounded():
    assert ev.tool_output("nmap", duration_s=1.23456).payload["duration_s"] == 1.235


def test_sequencing_sink_assigns_monotonic_seq():
    sink = ev.CollectingSink()
    sink.emit(ev.turn_start(0))
    sink.emit(ev.assistant("hi"))
    sink.emit(ev.turn_end(0))
    assert [e.seq for e in sink.events] == [0, 1, 2]
    assert sink.kinds() == ["turn_start", "assistant", "turn_end"]


def test_collecting_sink_satisfies_eventsink_protocol():
    sink = ev.CollectingSink()
    assert isinstance(sink, ev.EventSink)  # runtime_checkable Protocol


def test_events_are_json_roundtrippable():
    # Everything a producer can emit must survive json.dumps → the Go client
    # parses exactly this.
    for e in (
        ev.turn_start(1),
        ev.engine_phase("nmap → 3 findings", 3),
        ev.pre_hook("sqli-active"),
        ev.thinking("the user wants..."),
        ev.tool_started("nuclei", "https://x -tags cve", 2),
        ev.tool_output("nuclei", status="ok", duration_s=8.4, summary="2 findings", output="raw", step_id=2),
        ev.finding("MEDIUM", "cookie sin HttpOnly", cwe="CWE-1004", location="/", verified=True),
        ev.assistant("## Resultado\n- x"),
        ev.reflection("mismo tool 3x — actuá"),
        ev.turn_end(1),
        ev.done("# Report", 3),
        ev.error("timeout"),
    ):
        parsed = json.loads(json.dumps(e.to_dict(), ensure_ascii=False))
        assert parsed["kind"] == e.kind


# --------------------------------------------------------------------------- #
# SSESink — bridges the sync-emit turn pipeline to an async SSE generator.     #
# --------------------------------------------------------------------------- #


async def test_sse_sink_streams_buffered_events_then_ends_on_turn_end():
    sink = ev.SSESink()
    sink.emit(ev.turn_start(0))
    sink.emit(ev.assistant("hola"))
    sink.emit(ev.turn_end(0))  # closes the stream
    frames = [f async for f in sink.stream(poll_interval=0.001)]
    assert len(frames) == 3
    assert frames[0].startswith("event: turn_start\ndata: ")
    assert frames[-1].startswith("event: turn_end\ndata: ")


async def test_sse_sink_streams_events_arriving_concurrently():
    sink = ev.SSESink()

    async def _produce():
        for i in range(3):
            await asyncio.sleep(0.005)
            sink.emit(ev.tool_started(f"tool{i}"))
        sink.emit(ev.turn_end(0))

    task = asyncio.create_task(_produce())
    frames = [f async for f in sink.stream(poll_interval=0.001)]
    await task
    kinds = [f.split("event: ", 1)[1].split("\n", 1)[0] for f in frames]
    assert kinds == ["tool_started", "tool_started", "tool_started", "turn_end"]


async def test_sse_sink_close_terminates_stream_without_turn_end():
    sink = ev.SSESink()
    sink.emit(ev.assistant("partial"))

    async def _closer():
        await asyncio.sleep(0.01)
        sink.close()

    task = asyncio.create_task(_closer())
    frames = [f async for f in sink.stream(poll_interval=0.001)]
    await task
    assert len(frames) == 1  # only the buffered event, then close ended it


def test_callback_sink_calls_fn_per_event_with_seq():
    seen = []
    sink = ev.CallbackSink(lambda e: seen.append((e.kind, e.seq)))
    sink.emit(ev.turn_start(0))
    sink.emit(ev.done("r", 2))
    assert seen == [("turn_start", 0), ("done", 1)]


def test_callback_sink_swallows_callback_errors():
    def _boom(e):
        raise RuntimeError("consumer down")

    sink = ev.CallbackSink(_boom)
    sink.emit(ev.turn_start(0))  # must not raise — best-effort


def test_callback_sink_server_pattern_appends_sse_frames():
    # Exactly how the server wires it: push SSE frames onto a buffer.
    buffer: list[dict] = []
    sink = ev.CallbackSink(lambda e: buffer.append({"sse": e.to_sse()}))
    sink.emit(ev.tool_started("nmap"))
    sink.emit(ev.turn_end(0))
    assert len(buffer) == 2
    assert buffer[0]["sse"].startswith("event: tool_started\ndata: ")
