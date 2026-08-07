"""A malformed-tool_call HTTP 500 from the local model server must be recovered,
not fatal.

Regression: a local model inlined an SSH private key into a tool_call's JSON
arguments, llama.cpp answered ``500 - Failed to parse tool call arguments as
JSON``, and the run died one step from a foothold. The reflective runner now
treats it as a recoverable per-chunk fault: nudge the model off inlining big
payloads, retry, and only give up after a few consecutive failures.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from kryon.cli.reflective_runner import run_with_reflection


class _InternalServerError(Exception):
    """Mimics openai.InternalServerError by class name + message."""


def _ok_result() -> Mock:
    r = Mock()
    r.final_output = "done"
    r.new_items = []
    r.raw_responses = []
    return r


async def test_tool_call_500_is_recovered_and_run_continues():
    """First chunk hits the parse-error 500; the runner retries and finishes
    instead of propagating the exception."""
    calls = {"n": 0}

    async def _flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _InternalServerError(
                "Error code: 500 - Failed to parse tool call arguments as JSON"
            )
        return _ok_result()

    import kryon.sdk.agents.run as runmod

    with patch.object(runmod.Runner, "run", new=_flaky):
        result = await run_with_reflection(
            agent=Mock(),
            initial_input="go",
            reflect_every=2,
            max_total_turns=4,
        )

    assert calls["n"] >= 2  # retried after the 500 instead of dying
    assert result is not None


async def test_persistent_tool_call_500_ends_with_partial_report():
    """If every chunk 500s, the runner stops retrying after the bounded
    recoveries and ends GRACEFULLY with a partial report — it does not loop
    forever, and it does NOT propagate the exception (no crash one step from a
    foothold). This is the deterministic ``break``-with-partial-note contract."""
    calls = {"n": 0}

    async def _always_500(*args, **kwargs):
        calls["n"] += 1
        raise _InternalServerError(
            "Error code: 500 - Failed to parse tool call arguments as JSON"
        )

    import kryon.sdk.agents.run as runmod

    with patch.object(runmod.Runner, "run", new=_always_500):
        result = await run_with_reflection(
            agent=Mock(),
            initial_input="go",
            reflect_every=2,
            max_total_turns=20,
        )

    # Graceful: a partial result surfaces instead of the exception (if the
    # runner had re-raised, this test would error out before the asserts).
    assert result is not None
    assert "PARCIAL" in (getattr(result, "final_output", "") or "").upper()
    # Bounded retries: gave up well before burning all 20 turns.
    assert calls["n"] < 20
