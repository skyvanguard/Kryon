"""Kill-switch — hard external stop for an autonomous run.

Bounds HOW MUCH the agent acts and lets a human pull the plug mid-run. Tripping
raises KillSwitchTripped (an AgentsException) so the run STOPS rather than the
model swallowing it as an observation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from kryon.agents.killswitch import (
    KillSwitch,
    KillSwitchTripped,
    get_killswitch,
    reset_killswitch,
)


def test_inactive_when_nothing_set(monkeypatch):
    for v in ("KRYON_KILL_FILE", "KRYON_DEADLINE", "KRYON_MAX_ACTIONS"):
        monkeypatch.delenv(v, raising=False)
    reset_killswitch()
    assert get_killswitch() is None
    reset_killswitch()


def test_action_budget_trips_after_limit():
    ks = KillSwitch(None, None, max_actions=2)
    assert ks.check_and_count() == (False, None)  # action 1
    assert ks.check_and_count() == (False, None)  # action 2
    tripped, why = ks.check_and_count()  # action 3 > 2
    assert tripped and "budget" in why


def test_kill_file_trips_when_present(tmp_path):
    kf = tmp_path / "stop"
    ks = KillSwitch(str(kf), None, None)
    assert ks.check_and_count()[0] is False
    kf.write_text("x")
    assert ks.check_and_count()[0] is True


def test_deadline_trips_when_past():
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    ks = KillSwitch(None, past, None)
    assert ks.check_and_count()[0] is True


def test_deadline_future_does_not_trip():
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    ks = KillSwitch(None, future, None)
    assert ks.check_and_count()[0] is False


def test_get_killswitch_from_env(monkeypatch):
    monkeypatch.setenv("KRYON_MAX_ACTIONS", "5")
    reset_killswitch()
    ks = get_killswitch()
    assert ks is not None and ks.max_actions == 5
    reset_killswitch()


# ---------------------------------------------------------------------------
# Integration — the switch actually stops a run at the executor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_action_budget_stops_the_run(monkeypatch):
    monkeypatch.setenv("KRYON_MAX_ACTIONS", "1")
    reset_killswitch()
    try:
        from kryon.sdk.agents import Agent, Runner
        from kryon.sdk.agents.tool import function_tool
        from tests.core.test_responses import get_function_tool_call
        from tests.fake_model import FakeModel

        ran: list[int] = []

        @function_tool
        def step() -> str:
            """A no-arg action."""
            ran.append(1)
            return "ok"

        model = FakeModel()
        agent = Agent(name="t", model=model, tools=[step])
        # The model wants to act forever; the budget must stop it.
        model.add_multiple_turn_outputs(
            [
                [get_function_tool_call("step", json.dumps({}))],
                [get_function_tool_call("step", json.dumps({}))],
                [get_function_tool_call("step", json.dumps({}))],
            ]
        )
        with pytest.raises(KillSwitchTripped):
            await Runner.run(agent, input="go")
        # budget=1 → the first action runs, the second trips the switch.
        assert len(ran) == 1
    finally:
        reset_killswitch()
