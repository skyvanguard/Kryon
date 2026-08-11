"""E2E of the rich-events SSE path — the endpoint the Charm/TUI client drives.

``POST /runs {rich_events:true, stream:true}`` runs the full turn via
``turn_service.run_turn`` and pushes each ``AgentEvent`` as an SSE frame onto
``GET /runs/{id}/stream``. These tests drive that transport over the REAL
FastAPI app (TestClient) and assert the ``thinking`` + ``reflection`` frames
arrive in the exact wire shape the Go client parses (``event: <kind>`` +
``data: {kind, seq, ...payload}``) — the "live server" gap the wiring closed.

The LLM is stubbed so no GPU/network is needed; the transport, the
``CallbackSink.to_sse()`` encoding, and the ContextVar sink bridge are real.
"""

from __future__ import annotations

import json
import types


def _drain_sse(client, run_id, *, max_lines=400):
    """Read the SSE stream up to ``turn_end`` — the rich path's real terminal
    (the Go client's ``IsTerminal``), which ``turn_service`` emits AFTER its
    own ``done`` frame and before the server's trailing synthetic ``done``.
    Returns parsed frames as ``(event, data)`` tuples. Bails after
    ``max_lines`` so a stuck run can never hang the test."""
    frames: list[tuple[str, dict]] = []
    with client.stream("GET", f"/api/v1/runs/{run_id}/stream") as resp:
        assert resp.status_code == 200
        cur_event: str | None = None
        seen = 0
        for line in resp.iter_lines():
            seen += 1
            if seen > max_lines:
                break
            if line.startswith("event: "):
                cur_event = line[len("event: ") :]
            elif line.startswith("data: "):
                try:
                    payload = json.loads(line[len("data: ") :])
                except json.JSONDecodeError:
                    payload = {}
                frames.append((cur_event or payload.get("kind", ""), payload))
                if cur_event == "turn_end":
                    break
    return frames


def test_rich_events_streams_thinking_and_reflection(client, monkeypatch):
    """The reflective loop's thinking + reflection events reach the wire in the
    Go-parseable shape (kind + text/note), interleaved with tool + assistant."""

    async def _fake_reflection(agent, conv, *, event_sink=None, **kwargs):
        from kryon.services import agent_events as ev

        assert event_sink is not None, "server must pass a sink on the rich path"
        event_sink.emit(ev.thinking("el puerto 8009 es AJP — probar Ghostcat CVE-2020-1938"))
        event_sink.emit(ev.tool_started("nuclei"))
        event_sink.emit(ev.tool_output("nuclei", status="ok", output="ghostcat", duration_s=1.2))
        event_sink.emit(ev.reflection("loop detectado (nuclei) — replanteando · turno 4/14"))
        return types.SimpleNamespace(final_output="# Informe\nGhostcat presente")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _fake_reflection)

    resp = client.post(
        "/api/v1/runs",
        json={
            "agent_key": "kryon",
            "input": "hola",  # non-analysis → determinism no-ops (no nmap/network)
            "stream": True,
            "rich_events": True,
            "free_run": True,  # skip determinism + pre_hooks; isolate the reflective stream
            "max_turns": 4,
        },
    )
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]

    frames = _drain_sse(client, run_id)
    kinds = [ev for ev, _ in frames]

    # The two newly-wired kinds are present, in the Go wire format.
    assert "thinking" in kinds
    assert "reflection" in kinds
    # And the standard stream around them still flows.
    assert "turn_start" in kinds
    assert "tool_started" in kinds
    assert "assistant" in kinds
    assert "turn_end" in kinds

    # Payload shapes match the Go struct tags (events.go): text / note / kind / seq.
    thinking = next(p for k, p in frames if k == "thinking")
    assert thinking["kind"] == "thinking"
    assert "seq" in thinking
    assert thinking["text"].startswith("el puerto 8009")

    reflection = next(p for k, p in frames if k == "reflection")
    assert reflection["kind"] == "reflection"
    assert reflection["note"].startswith("loop detectado (nuclei)")


def test_rich_events_thinking_via_real_bridge(client, monkeypatch):
    """The ContextVar sink bridge works through the REAL run_with_reflection:
    it binds the sink, and a ``emit_thinking`` from where the model layer sits
    (stubbed ``Runner.run``) routes to the sink → CallbackSink → SSE."""

    async def _fake_runner_run(agent, **kwargs):
        # Simulate what openai_native._fetch_response does after a response:
        # emit the model's reasoning through the per-task bridge.
        from kryon.services.event_sink_runtime import emit_thinking

        emit_thinking("razonando desde la capa del modelo — bridge vivo")
        return types.SimpleNamespace(
            final_output="# Informe\nlisto",
            raw_responses=[],
            new_items=[],
            to_input_list=lambda: [],
        )

    monkeypatch.setattr("kryon.sdk.agents.run.Runner.run", _fake_runner_run)

    resp = client.post(
        "/api/v1/runs",
        json={
            "agent_key": "kryon",
            "input": "hola",
            "stream": True,
            "rich_events": True,
            "free_run": True,
            "max_turns": 4,
        },
    )
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]

    frames = _drain_sse(client, run_id)
    thinking = [p for k, p in frames if k == "thinking"]
    assert thinking, "the model-layer bridge did not reach the SSE stream"
    assert any("bridge vivo" in p.get("text", "") for p in thinking)
