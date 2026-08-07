"""Turn-service — composes determinism → pre_hooks → run_with_reflection and
emits the full AgentEvent stream. These mock the heavy pieces (orchestrator,
pre_hooks, reflective loop) and assert the event sequence a front-end renders."""

from __future__ import annotations

import types

from kryon.services import turn_service
from kryon.services.agent_events import CollectingSink, tool_started


def test_append_ground_truth_str_and_list():
    assert turn_service._append_ground_truth("hola", " GT") == "hola GT"
    msgs = [{"role": "user", "content": "audit"}]
    turn_service._append_ground_truth(msgs, " GT")
    assert msgs[-1]["content"] == "audit GT"
    # empty suffix is a no-op
    assert turn_service._append_ground_truth("x", "") == "x"


async def test_free_run_skips_determinism_and_streams_turn(monkeypatch):
    async def _fake_reflection(agent, conv, *, event_sink, max_total_turns, run_config):
        event_sink.emit(tool_started("web_fetch_smart"))  # live tool event flows through
        return types.SimpleNamespace(final_output="# Report\nSin vulns")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _fake_reflection)

    sink = CollectingSink()
    out = await turn_service.run_turn(object(), "auditá https://x", sink=sink, free_run=True)

    kinds = sink.kinds()
    assert kinds[0] == "turn_start"
    assert kinds[-1] == "turn_end"
    assert "tool_started" in kinds  # the reflective loop's live event
    assert "assistant" in kinds
    assert "done" in kinds
    assert "engine_phase" not in kinds  # determinism skipped in free-run
    assert out["findings_count"] == 0


async def test_determinism_emits_engine_phase_and_findings(monkeypatch):
    finding = types.SimpleNamespace(
        severity="HIGH",
        message="Check Point Gateway expuesto",
        cwe="CWE-1395",
        url="",
        host="example.com.py",
        needs_verification=False,
    )
    res = types.SimpleNamespace(findings=[finding], ground_truth="\n\n[GROUND TRUTH]\n", note="")

    monkeypatch.setattr("kryon.repl.engine_phase.resolve_target", lambda ui, st: "https://x")
    monkeypatch.setattr("kryon.repl.engine_phase.is_analysis_request", lambda ui: True)
    monkeypatch.setattr("kryon.services.target_orchestrator.run_target_orchestration", lambda *a, **k: res)

    async def _no_prehooks(agent, ui, console, *, session_target):
        return ""

    monkeypatch.setattr("kryon.skills.pre_hook_integration.maybe_run_pre_hooks", _no_prehooks)

    seen_conv = {}

    async def _fake_reflection(agent, conv, *, event_sink, max_total_turns, run_config):
        seen_conv["conv"] = conv
        return types.SimpleNamespace(final_output="done")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _fake_reflection)

    sink = CollectingSink()
    out = await turn_service.run_turn(object(), "auditá https://x", sink=sink)

    kinds = sink.kinds()
    assert "engine_phase" in kinds
    assert "finding" in kinds
    assert out["findings_count"] == 1
    # ground truth was appended to what the reflective loop received
    assert "[GROUND TRUTH]" in seen_conv["conv"]
    fev = next(e for e in sink.events if e.kind == "finding")
    assert fev.payload["severity"] == "HIGH"
    assert fev.payload["cwe"] == "CWE-1395"
    assert fev.payload["location"] == "example.com.py"  # falls back to host when url empty
    assert fev.payload["verified"] is True


async def test_reflection_error_emits_error_and_always_closes(monkeypatch):
    async def _boom(agent, conv, *, event_sink, max_total_turns, run_config):
        raise RuntimeError("model down")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _boom)

    sink = CollectingSink()
    out = await turn_service.run_turn(object(), "hi", sink=sink, free_run=True)

    kinds = sink.kinds()
    assert "error" in kinds
    assert kinds[-1] == "turn_end"  # the stream terminates cleanly even on failure
    assert out["findings_count"] == 0


async def test_engine_phase_failure_is_isolated(monkeypatch):
    # Determinism blowing up must not sink the turn — it emits an error and the
    # reflective loop still runs.
    monkeypatch.setattr("kryon.repl.engine_phase.resolve_target", lambda ui, st: "https://x")
    monkeypatch.setattr("kryon.repl.engine_phase.is_analysis_request", lambda ui: True)

    def _boom(*a, **k):
        raise RuntimeError("nmap exploded")

    monkeypatch.setattr("kryon.services.target_orchestrator.run_target_orchestration", _boom)

    async def _no_prehooks(agent, ui, console, *, session_target):
        return ""

    monkeypatch.setattr("kryon.skills.pre_hook_integration.maybe_run_pre_hooks", _no_prehooks)

    async def _fake_reflection(agent, conv, *, event_sink, max_total_turns, run_config):
        return types.SimpleNamespace(final_output="ok")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _fake_reflection)

    sink = CollectingSink()
    await turn_service.run_turn(object(), "auditá https://x", sink=sink)
    kinds = sink.kinds()
    assert "error" in kinds  # engine phase error surfaced
    assert "done" in kinds  # but the turn still completed
