"""End-to-end proof that the scope cage blocks at the REAL tool executor.

A side-effecting tool records whether it actually ran. With KRYON_SCOPE set, an
out-of-scope tool call must be refused BEFORE the tool body executes (the list
stays empty) and the model must receive a BLOCKED observation. The in-scope call
must run normally. This is the wiring the passive-gate bug lacked.
"""

from __future__ import annotations

import json

import pytest

from kryon.agents.authorization import reset_authorization
from kryon.sdk.agents import Agent, Runner
from kryon.sdk.agents.tool import function_tool
from tests.core.test_responses import get_function_tool_call, get_text_message
from tests.fake_model import FakeModel


def _tool_with_recorder():
    ran: list[str] = []

    @function_tool
    def probe(target: str) -> str:
        """Probe a target (records that it executed)."""
        ran.append(target)
        return f"RAN against {target}"

    return probe, ran


@pytest.mark.asyncio
async def test_out_of_scope_call_blocked_before_execution(monkeypatch):
    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    reset_authorization()
    try:
        probe, ran = _tool_with_recorder()
        model = FakeModel()
        agent = Agent(name="t", model=model, tools=[probe])
        model.add_multiple_turn_outputs(
            [
                [get_function_tool_call("probe", json.dumps({"target": "8.8.8.8"}))],
                [get_text_message("done")],
            ]
        )
        result = await Runner.run(agent, input="go")

        # The tool body NEVER ran — the cage intercepted at the executor.
        assert ran == []
        # The model received a BLOCKED observation it can adapt to.
        convo = " ".join(str(x) for x in result.to_input_list())
        assert "BLOCKED by engagement cage" in convo
    finally:
        reset_authorization()


@pytest.mark.asyncio
async def test_in_scope_call_runs_normally(monkeypatch):
    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    reset_authorization()
    try:
        probe, ran = _tool_with_recorder()
        model = FakeModel()
        agent = Agent(name="t", model=model, tools=[probe])
        model.add_multiple_turn_outputs(
            [
                [get_function_tool_call("probe", json.dumps({"target": "10.0.0.5"}))],
                [get_text_message("done")],
            ]
        )
        result = await Runner.run(agent, input="go")

        assert ran == ["10.0.0.5"]
        convo = " ".join(str(x) for x in result.to_input_list())
        assert "RAN against 10.0.0.5" in convo
    finally:
        reset_authorization()


@pytest.mark.asyncio
async def test_no_scope_means_no_enforcement(monkeypatch):
    monkeypatch.delenv("KRYON_SCOPE", raising=False)
    reset_authorization()
    try:
        probe, ran = _tool_with_recorder()
        model = FakeModel()
        agent = Agent(name="t", model=model, tools=[probe])
        model.add_multiple_turn_outputs(
            [
                [get_function_tool_call("probe", json.dumps({"target": "8.8.8.8"}))],
                [get_text_message("done")],
            ]
        )
        await Runner.run(agent, input="go")
        # Cage inactive → the out-of-scope target runs (backward compatible).
        assert ran == ["8.8.8.8"]
    finally:
        reset_authorization()
