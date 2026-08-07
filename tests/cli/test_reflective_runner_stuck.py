"""Fix-pivot regression: a StuckError raised inside a chunk must NOT
propagate out of run_with_reflection. The runner finalizes gracefully so
the caller (kryon investigate) still produces a PARTIAL report instead of
dying with no artifact.

Before the fix, StuckError fell through to the `raise` at the end of the
chunk `except` block → run_investigate caught it and returned 6 with no
report. Now the runner converts it into a returned result carrying a
"stuck loop" note + whatever the capture hooks salvaged.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.sdk.agents.exceptions import StuckError


async def test_stuck_error_finalizes_with_partial_result(monkeypatch):
    import kryon.sdk.agents.run as run_mod

    class _StuckRunner:
        @staticmethod
        async def run(agent, **kwargs):  # noqa: ARG004 — signature parity
            raise StuckError(tool_name="run_command", repeat_count=4, window_size=6)

    monkeypatch.setattr(run_mod, "Runner", _StuckRunner)

    from kryon.cli.reflective_runner import run_with_reflection

    result = await run_with_reflection(
        SimpleNamespace(name="kryon"),  # agent — only forwarded to Runner.run
        initial_input="audit https://target.example",
        reflect_every=4,
        max_total_turns=8,
    )

    assert result is not None, "stuck run must finalize with a result, not None/raise"
    final = (getattr(result, "final_output", "") or "").lower()
    assert "loop irrecuperable" in final, f"missing stuck note in final_output: {final!r}"


async def test_stuck_error_preserves_prior_final_output(monkeypatch):
    """If a clean chunk completed before the loop tripped, its final_output
    is kept and the stuck note is appended (not replaced)."""
    import kryon.sdk.agents.run as run_mod

    calls = {"n": 0}

    class _FlipRunner:
        @staticmethod
        async def run(agent, **kwargs):  # noqa: ARG004
            calls["n"] += 1
            if calls["n"] == 1:
                # First chunk "finishes" with a real answer but leaves a
                # pending tool call so the loop continues to a 2nd chunk.
                return SimpleNamespace(
                    final_output="found endpoint /rest/products",
                    new_items=[],
                    raw_responses=[object()],
                    _pending=True,
                )
            raise StuckError(tool_name="curl", repeat_count=4, window_size=6)

    monkeypatch.setattr(run_mod, "Runner", _FlipRunner)
    # Force the first result to look "not finished" so the loop runs a 2nd chunk.
    monkeypatch.setattr(
        "kryon.cli.reflective_runner._has_pending_tool_calls",
        lambda r: getattr(r, "_pending", False),
    )

    from kryon.cli.reflective_runner import run_with_reflection

    result = await run_with_reflection(
        SimpleNamespace(name="kryon"),
        initial_input="audit https://target.example",
        reflect_every=4,
        max_total_turns=8,
    )
    final = getattr(result, "final_output", "") or ""
    assert "found endpoint /rest/products" in final
    assert "loop irrecuperable" in final.lower()


async def test_persistent_stuck_tool_aborts_before_max_turns(monkeypatch):
    """A weak model that re-issues the SAME tool+args every chunk must be
    cut off well before max_total_turns — not allowed to spin to the budget
    (observed: qwen3-8b re-fetching one URL ~48× to the 50-turn cap)."""
    import kryon.cli.reflective_runner as rr
    import kryon.sdk.agents.run as run_mod

    calls = {"n": 0}

    class _SpinRunner:
        @staticmethod
        async def run(agent, **kwargs):  # noqa: ARG004
            calls["n"] += 1
            return SimpleNamespace(final_output="", new_items=[object()], raw_responses=[object()], _pending=True)

    monkeypatch.setattr(run_mod, "Runner", _SpinRunner)
    # Every chunk yields the SAME two identical tool calls → _is_stuck fires
    # each chunk, so consecutive_stuck_count crosses the abort trigger.
    rec = rr._ToolCallRecord(tool_name="web_fetch_smart", args_hash="samehash", args_preview="url=https://t/")
    monkeypatch.setattr(rr, "_extract_tool_calls", lambda items: [rec, rec])
    # Keep the loop going (agent never "finishes") so only the stuck-abort
    # can stop it.
    monkeypatch.setattr(rr, "_has_pending_tool_calls", lambda r: True)

    result = await rr.run_with_reflection(
        SimpleNamespace(name="kryon"),
        initial_input="audita https://t.example",
        reflect_every=2,
        max_total_turns=40,  # 20 chunks if never aborted
    )

    # Aborted within a few chunks (trigger=3), not the full 20.
    assert calls["n"] <= rr._DEFAULT_STUCK_ABORT_TRIGGER + 1, f"did not abort early: {calls['n']} chunks ran"
    final = (getattr(result, "final_output", "") or "").lower()
    assert "bucle detectado" in final, f"missing stuck-abort summary: {final!r}"


async def test_no_clean_result_still_reports_captured_tools(monkeypatch):
    """Wall-budget / all-MaxTurns end with no clean chunk result → last_result
    is None, but the agent DID run tools (captured by hooks). The runner must
    build a carrier so the report shows the tool activity, not 'Tool calls: 0'.
    """
    import kryon.sdk.agents.run as run_mod

    class _MaxTurnsExceeded(Exception):
        pass

    class _ToolThenMaxTurns:
        @staticmethod
        async def run(agent, **kwargs):  # noqa: ARG004
            hooks = kwargs.get("hooks")
            if hooks is not None:
                tool = SimpleNamespace(name="web_fetch_smart")
                await hooks.on_tool_start(None, agent, tool)
                await hooks.on_tool_end(None, agent, tool, "HTTP 200 OK")
            raise _MaxTurnsExceeded("chunk budget exhausted")

    monkeypatch.setattr(run_mod, "Runner", _ToolThenMaxTurns)

    from kryon.cli.reflective_runner import run_with_reflection

    result = await run_with_reflection(
        SimpleNamespace(name="kryon"),
        initial_input="audita https://t.example",
        reflect_every=4,
        max_total_turns=4,
    )
    assert result is not None, "must build a carrier when tools ran but no clean result"
    chain = getattr(result, "_captured_chain", []) or []
    assert any(step.get("tool") == "web_fetch_smart" for step in chain), (
        f"captured tool activity must be reported, got chain={chain}"
    )
