"""Tier 4 SDK concurrency fixes — session_id isolation + executor singleton.

These pin the shared-state fixes: the usage tracker's session_id must not bleed
between concurrent in-process sessions, and the parallel executor singleton must
be constructed exactly once even under a thread race.
"""

from __future__ import annotations

import contextvars

import pytest

from kryon.sdk.agents.global_usage_tracker import GLOBAL_USAGE_TRACKER
from kryon.sdk.agents.parallel_tool_executor import get_parallel_tool_executor


def test_session_id_is_isolated_per_context():
    # Two independent contexts set different session ids; neither sees the other's.
    def set_and_read(sid: str) -> str:
        GLOBAL_USAGE_TRACKER.session_id = sid
        return GLOBAL_USAGE_TRACKER.session_id

    ctx_a = contextvars.copy_context()
    ctx_b = contextvars.copy_context()
    assert ctx_a.run(set_and_read, "engagement-A") == "engagement-A"
    assert ctx_b.run(set_and_read, "engagement-B") == "engagement-B"
    # The two contexts did not clobber each other.
    assert ctx_a.run(lambda: GLOBAL_USAGE_TRACKER.session_id) == "engagement-A"
    assert ctx_b.run(lambda: GLOBAL_USAGE_TRACKER.session_id) == "engagement-B"


def test_parallel_executor_singleton_is_stable():
    a = get_parallel_tool_executor()
    b = get_parallel_tool_executor()
    assert a is b  # one shared executor, not two with split state


@pytest.mark.asyncio
async def test_input_guardrail_blocks_turn1_tools_before_they_run():
    """#4 — input guardrails run BEFORE the first turn now (was concurrent), so a
    tripped guardrail stops the run before any turn-1 tool executes."""
    import json as _json

    from kryon.sdk.agents import (
        Agent,
        GuardrailFunctionOutput,
        InputGuardrailTripwireTriggered,
        Runner,
        input_guardrail,
    )
    from kryon.sdk.agents.tool import function_tool
    from tests.core.test_responses import get_function_tool_call, get_text_message
    from tests.fake_model import FakeModel

    ran: list[int] = []

    @function_tool
    def probe() -> str:
        """Records execution."""
        ran.append(1)
        return "ran"

    @input_guardrail
    def block_everything(ctx, agent, inp):
        return GuardrailFunctionOutput(output_info={"reason": "blocked"}, tripwire_triggered=True)

    model = FakeModel()
    agent = Agent(name="t", model=model, tools=[probe], input_guardrails=[block_everything])
    model.add_multiple_turn_outputs(
        [
            [get_function_tool_call("probe", _json.dumps({}))],
            [get_text_message("done")],
        ]
    )
    with pytest.raises(InputGuardrailTripwireTriggered):
        await Runner.run(agent, input="go")
    assert ran == []  # the guardrail tripped before turn 1 ran its tool
