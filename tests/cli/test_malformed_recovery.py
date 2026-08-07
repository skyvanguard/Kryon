"""Harness robustness: a malformed tool_call (llama.cpp HTTP 500 "Failed to parse tool call
arguments") must NOT crash the whole reflective run. Found live on THM Internal — Ornith re-emitted a
291-username inline list, the JSON broke, and the run died at turn 20 with all the brute-force progress
lost. The runner now hard-resets the model off the stuck approach and continues (bounded), ending with a
partial report instead of raising.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import kryon.cli.reflective_runner as rr


class _ServerErr(Exception):
    status_code = 500


def _make_boom(counter: list[int]):
    async def _boom(*_a, **_k):
        counter[0] += 1
        raise _ServerErr(
            "Error code: 500 - Failed to parse tool call arguments: parse error; last read: 'BLOB'"
        )

    return _boom


def _agent() -> SimpleNamespace:
    return SimpleNamespace(
        name="t", tools=[], model=None, instructions="x",
        handoffs=[], input_guardrails=[], output_guardrails=[],
    )


def test_repeated_malformed_toolcall_recovers_instead_of_raising(monkeypatch):
    """A stubbornly-repeated malformed tool_call → recover + partial report, never raise."""
    from kryon.sdk.agents import run as sdk_run

    calls = [0]
    monkeypatch.setattr(sdk_run.Runner, "run", _make_boom(calls))

    # Must NOT raise (the old code re-raised → InternalServerError killed the run).
    out = asyncio.run(rr.run_with_reflection(_agent(), "probe", reflect_every=4, max_total_turns=8))
    assert out is not None  # returns a (partial) result instead of crashing
    # The runner retried/recovered rather than bailing on the first 500.
    assert calls[0] >= 2, f"expected recovery retries, got only {calls[0]} Runner.run call(s)"
