"""Turn-service — run ONE full Kryon turn and emit AgentEvents to a sink.

This is the driveable core the whole TUI foundation is for: the SAME stack the
REPL runs per turn —

    deterministic engine/orchestrator  →  pre_hooks  →  run_with_reflection

— but instead of rendering inline with Rich prints, it emits structured
``AgentEvent``s to an ``EventSink`` (``services.agent_events``). A front-end
decides how to render them:

- the SSE server (``/runs`` stream) → ``event:``/``data:`` frames,
- a future Go/Charm TUI → parses that JSON,
- the REPL (later) → a ``ConsoleSink``, byte-for-byte its current look.

The determinism is preserved (that's the moat — the free-model run wanders and
CoT-loops without it), so the TUI shows a REAL Kryon, not a raw agent. Tool
events flow LIVE from ``run_with_reflection(event_sink=...)`` via
``ItemCaptureHooks``; the turn-service adds the turn/engine/finding/assistant/done
bookends around them.
"""

from __future__ import annotations

from typing import Any


def _append_ground_truth(conversation_input: Any, suffix: str) -> Any:
    """Concat injected ground-truth to the user message, str- or message-list-shaped
    (mirrors the two branches in cli/_original.py)."""
    if not suffix:
        return conversation_input
    if isinstance(conversation_input, str):
        return conversation_input + suffix
    if isinstance(conversation_input, list) and conversation_input:
        last = conversation_input[-1]
        if isinstance(last, dict) and last.get("role") == "user":
            last["content"] = last.get("content", "") + suffix
    return conversation_input


def _run_determinism(agent: Any, user_input: str, session_target: str | None, sink: Any, console: Any, discover: bool):
    """Deterministic engine/orchestrator phase. Emits engine_phase + one finding
    event per deterministic finding; returns (ground_truth_suffix, findings_count).
    Best-effort — a failure emits an error event and yields no ground truth."""
    from kryon.services import agent_events as ev

    try:
        from kryon.repl.engine_phase import is_analysis_request, resolve_target

        tgt = resolve_target(user_input, session_target)
        if not (tgt and is_analysis_request(user_input)):
            return "", 0

        from kryon.services.target_orchestrator import run_target_orchestration

        # Immediate progress notice — the orchestration below (nmap discovery →
        # per-service battery → compliance) runs synchronously for minutes and
        # emits nothing until it returns. Without this the front-end shows a blank
        # "working…" for the whole discovery, reading as a hang.
        sink.emit(ev.engine_phase(f"detección determinista sobre {tgt} — discovery + batería (puede tardar)…"))
        res = run_target_orchestration(tgt, console=console, agent=agent, discover=discover)
        sink.emit(ev.engine_phase(res.note or f"determinismo: {len(res.findings)} hallazgos", len(res.findings)))
        for f in res.findings:
            sink.emit(
                ev.finding(
                    getattr(f, "severity", "INFO"),
                    getattr(f, "message", ""),
                    cwe=getattr(f, "cwe", ""),
                    location=getattr(f, "url", "") or getattr(f, "host", ""),
                    verified=not getattr(f, "needs_verification", False),
                )
            )
        return res.ground_truth or "", len(res.findings)
    except Exception as e:  # noqa: BLE001 — determinism is best-effort
        sink.emit(ev.error(f"engine phase: {type(e).__name__}: {e}"))
        return "", 0


async def _run_pre_hooks(agent: Any, user_input: str, session_target: str | None, console: Any) -> str:
    """Run skill pre_hooks; return the ground-truth suffix (empty on none/failure)."""
    from kryon.services import agent_events as ev

    try:
        from kryon.skills.pre_hook_integration import maybe_run_pre_hooks

        return await maybe_run_pre_hooks(agent, user_input, console, session_target=session_target) or ""
    except Exception as e:  # noqa: BLE001
        sink_error = getattr(console, "_kryon_sink", None)
        if sink_error is not None:
            sink_error.emit(ev.error(f"pre_hooks: {e}"))
        return ""


async def run_turn(
    agent: Any,
    user_input: str,
    *,
    sink: Any,
    session_target: str | None = None,
    max_turns: int = 30,
    run_config: Any = None,
    free_run: bool = False,
    discover: bool = True,
) -> dict[str, Any]:
    """Run one full Kryon turn, emitting AgentEvents to ``sink``.

    Args:
        agent: the unified Kryon agent.
        user_input: the user's natural-language request.
        sink: an ``EventSink`` (``services.agent_events``).
        session_target: sticky target resolved from a prior turn, if any.
        max_turns: reflective-loop turn budget.
        run_config: SDK RunConfig passthrough.
        free_run: skip the determinism + pre_hooks (the KRYON_NO_DETERMINISM
            experiment — the model drives alone; expect wandering).
        discover: run the nmap discovery step of the orchestrator.

    Returns a small summary dict (``findings_count``). Never raises — failures
    are emitted as an ``error`` event so the stream always terminates cleanly.
    """
    from io import StringIO

    from rich.console import Console

    from kryon.services import agent_events as ev

    # A throwaway console for the determinism/pre_hook helpers, which still print
    # internally; their events reach the front-end via the sink, not this console.
    null_console = Console(file=StringIO(), force_terminal=False)
    null_console._kryon_sink = sink  # let _run_pre_hooks surface errors  # type: ignore[attr-defined]

    sink.emit(ev.turn_start(0))
    conversation_input: Any = user_input
    findings_count = 0
    final_output = ""

    try:
        if not free_run:
            gt, fc = _run_determinism(agent, user_input, session_target, sink, null_console, discover)
            conversation_input = _append_ground_truth(conversation_input, gt)
            findings_count += fc

            suffix = await _run_pre_hooks(agent, user_input, session_target, null_console)
            conversation_input = _append_ground_truth(conversation_input, suffix)

        from kryon.cli.reflective_runner import run_with_reflection

        result = await run_with_reflection(
            agent,
            conversation_input,
            event_sink=sink,  # tool_started/tool_output flow live from here
            max_total_turns=max_turns,
            run_config=run_config,
        )
        final_output = str(getattr(result, "final_output", "") or "")
        if final_output.strip():
            sink.emit(ev.assistant(final_output))
        # `done` is the turn's terminal signal + findings tally — NOT a second copy
        # of the report. The narrative already rode the `assistant` event (with the
        # ◇ Kryon sello); repeating it in `report_markdown` made every front-end that
        # renders both (Charm TUI + REPL ConsoleSink) print the final report TWICE.
        sink.emit(ev.done("", findings_count))
    except Exception as e:  # noqa: BLE001 — the stream must always end cleanly
        sink.emit(ev.error(f"{type(e).__name__}: {e}"))
    finally:
        sink.emit(ev.turn_end(0))

    return {"findings_count": findings_count, "final_output": final_output}


__all__ = ["run_turn"]
