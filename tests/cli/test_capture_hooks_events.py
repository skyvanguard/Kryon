"""ItemCaptureHooks event emission — the live enganche for the turn-service.

When given an EventSink, the RunHooks fired by Runner.run on every tool call
also emit tool_started / tool_output AgentEvents, so a front-end (SSE / Go TUI)
sees tools fire in real time. With no sink (the REPL default) it's a no-op —
these tests lock both paths.
"""

from __future__ import annotations

import types

from kryon.cli.reflective_runner import ItemCaptureHooks
from kryon.services.agent_events import CollectingSink


def _tool(name: str):
    return types.SimpleNamespace(name=name)


async def test_emits_tool_started_then_tool_output():
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("nmap")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, "22/tcp open ssh\n80/tcp open http")
    assert sink.kinds() == ["tool_started", "tool_output"]
    started, output = sink.events
    assert started.payload["tool"] == "nmap"
    assert output.payload["tool"] == "nmap"
    assert output.payload["status"] == "ok"
    assert "ssh" in output.payload["output"]


async def test_error_status_inferred_from_output():
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("run_command")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, "curl: [exit code 6]")
    out = sink.events[-1]
    assert out.kind == "tool_output"
    assert out.payload["status"] == "error"


async def test_large_output_collapsed_in_event_body():
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("run_command")
    big = "line\n" * 50  # > 8 lines
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, big)
    out = sink.events[-1]
    assert out.payload["collapsed"] is True
    assert out.payload["output"] != ""  # body preserved for the front-end preview
    assert "lines" in out.payload["summary"]


async def test_step_ids_increment_across_tools():
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    for name in ("nmap", "nuclei"):
        t = _tool(name)
        await hooks.on_tool_start(None, None, t)
        await hooks.on_tool_end(None, None, t, "ok")
    starts = [e for e in sink.events if e.kind == "tool_started"]
    assert [s.payload["step_id"] for s in starts] == [1, 2]


async def test_no_sink_is_noop_and_still_captures_chain():
    # Default path (REPL): no sink → no events, but items still captured for the
    # reflective runner's chain reconstruction. Must never raise.
    hooks = ItemCaptureHooks()  # event_sink=None
    tool = _tool("nmap")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, "22/tcp open ssh")
    chain = hooks.to_chain()
    assert chain and chain[0]["tool"] == "nmap"


async def test_confirmed_validate_emits_a_finding_after_tool_output():
    # A validate_* tool that CONFIRMED an exploit streams a `finding` right after
    # its tool_output — so a front-end counts the model's loop confirmations, not
    # only the deterministic phase's findings.
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("validate_sqli")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, '{"validation_status": "confirmed", "url": "http://x/rest"}')
    assert sink.kinds() == ["tool_started", "tool_output", "finding"]
    fnd = sink.events[-1]
    assert fnd.payload["severity"] == "CRITICAL"  # sqli → db_takeover reaches impact
    assert fnd.payload["cwe"] == "CWE-89"
    assert fnd.payload["verified"] is True
    assert "validate_sqli" in fnd.payload["detail"]


async def test_confirmed_xss_is_high_not_critical():
    # XSS confirmation is validado-but-not-impact (session_risk) → HIGH, mirroring
    # the funnel's honest distinction.
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("validate_xss")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, '{"validation_status": "confirmed"}')
    fnd = sink.events[-1]
    assert fnd.kind == "finding"
    assert fnd.payload["severity"] == "HIGH"
    assert fnd.payload["cwe"] == "CWE-79"


async def test_unconfirmed_validate_emits_no_finding():
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("validate_sqli")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, '{"validation_status": "not_confirmed"}')
    assert sink.kinds() == ["tool_started", "tool_output"]  # no finding


async def test_non_validation_tool_emits_no_finding():
    sink = CollectingSink()
    hooks = ItemCaptureHooks(event_sink=sink)
    tool = _tool("nmap")
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, '{"validation_status": "confirmed"}')  # not a validate_* tool
    assert "finding" not in sink.kinds()


async def test_no_sink_confirmed_validate_is_noop():
    hooks = ItemCaptureHooks()  # no sink
    tool = _tool("validate_rce")
    await hooks.on_tool_start(None, None, tool)
    # Must not raise and must still capture the chain.
    await hooks.on_tool_end(None, None, tool, '{"validation_status": "confirmed"}')
    assert hooks.to_chain()[0]["tool"] == "validate_rce"


async def test_bad_sink_never_breaks_the_run():
    class _BoomSink:
        def emit(self, event):
            raise RuntimeError("sink down")

    hooks = ItemCaptureHooks(event_sink=_BoomSink())
    tool = _tool("nmap")
    # Emission is best-effort — a broken sink must not propagate into the run.
    await hooks.on_tool_start(None, None, tool)
    await hooks.on_tool_end(None, None, tool, "ok")
    assert hooks.to_chain()  # the run's own capture still worked
