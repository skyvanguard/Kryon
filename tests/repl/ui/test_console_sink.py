"""ConsoleSink renders AgentEvents to Rich, reproducing the REPL look. These
capture the console output and assert the event content actually renders — proof
the event protocol drives the existing renderers end-to-end."""

from __future__ import annotations

from rich.console import Console

from kryon.repl.ui.console_sink import ConsoleSink
from kryon.services import agent_events as ev


def _sink():
    console = Console(record=True, width=100)
    return ConsoleSink(console), console


def test_tool_started_renders_tool_name():
    sink, console = _sink()
    sink.emit(ev.tool_started("nmap", "10.0.0.1 -sV"))
    assert "nmap" in console.export_text()


def test_tool_output_renders_summary():
    sink, console = _sink()
    sink.emit(ev.tool_output("nuclei", status="ok", duration_s=8.4, summary="2 findings", output="raw"))
    assert "2 findings" in console.export_text()


def test_finding_renders_severity_and_detail():
    sink, console = _sink()
    sink.emit(ev.finding("HIGH", "Check Point Gateway expuesto"))
    out = console.export_text()
    assert "HIGH" in out
    assert "Check Point" in out


def test_assistant_renders_sello_and_markdown():
    sink, console = _sink()
    sink.emit(ev.assistant("# Resultado\nSin vulns de impacto"))
    out = console.export_text()
    assert "Kryon" in out  # the ◇ Kryon sello
    assert "Resultado" in out


def test_engine_phase_renders_note():
    sink, console = _sink()
    sink.emit(ev.engine_phase("nmap → 9 findings deterministas", 9))
    assert "9 findings" in console.export_text()


def test_error_renders_message():
    sink, console = _sink()
    sink.emit(ev.error("timeout del target"))
    assert "timeout del target" in console.export_text()


def test_malformed_or_unknown_event_never_raises():
    sink, _ = _sink()
    sink.emit(ev.AgentEvent("tool_output", {}))  # missing keys → defaults
    sink.emit(ev.AgentEvent("finding", {}))
    sink.emit(ev.AgentEvent("totally_unknown_kind", {"x": 1}))
    # reaching here = no exception propagated (render is best-effort)


def test_sink_sequences_events_via_base():
    sink, _ = _sink()
    sink.emit(ev.turn_start(0))
    sink.emit(ev.assistant("hi"))
    sink.emit(ev.turn_end(0))
    assert sink._seq == 3
