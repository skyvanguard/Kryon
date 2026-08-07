"""Forced closing synthesis. A capable model explores until the reflective loop cuts
it off at max_turns/wall budget without ever summarizing, leaving final_output empty and
the report showing "(el agente no produjo salida final)". _force_final_synthesis runs ONE
toolless closing turn so the agent's analysis lands in the report instead.
"""

from __future__ import annotations

import types
from unittest.mock import patch

from kryon.cli.reflective_runner import _force_final_synthesis


class _FakeAgent:
    def __init__(self) -> None:
        self.cloned_with: dict | None = None

    def clone(self, **kwargs):
        self.cloned_with = kwargs
        return self  # the toolless clone stands in for the real agent


def _result(final_output: str):
    return types.SimpleNamespace(final_output=final_output)


async def test_kill_switch_returns_empty(monkeypatch):
    monkeypatch.setenv("KRYON_FINAL_SYNTHESIS", "false")
    out = await _force_final_synthesis(_FakeAgent(), None, None)
    assert out == ""


async def test_synthesizes_over_history(monkeypatch):
    monkeypatch.delenv("KRYON_FINAL_SYNTHESIS", raising=False)
    agent = _FakeAgent()
    captured: dict = {}

    async def _fake_run(a, *, input, max_turns, run_config):  # noqa: A002 — mirror SDK kwarg name
        captured["input"] = input
        captured["max_turns"] = max_turns
        return _result("## Veredicto\nSin impacto más allá de lo determinista.")

    import kryon.sdk.agents.run as runmod

    with patch.object(runmod.Runner, "run", new=_fake_run):
        out = await _force_final_synthesis(
            agent,
            [{"role": "user", "content": "prev"}],
            None,
        )

    assert "Veredicto" in out
    # The agent was cloned WITHOUT tools (synthesis can't call anything).
    assert agent.cloned_with == {"tools": []}
    # One closing turn, over the accumulated history + the synthesis prompt.
    assert captured["max_turns"] == 1
    assert isinstance(captured["input"], list)
    assert captured["input"][-1]["role"] == "user"
    assert "reporte final" in captured["input"][-1]["content"]


async def test_empty_final_output_returns_empty(monkeypatch):
    monkeypatch.delenv("KRYON_FINAL_SYNTHESIS", raising=False)

    async def _fake_run(a, *, input, max_turns, run_config):  # noqa: A002
        return types.SimpleNamespace(final_output="")

    import kryon.sdk.agents.run as runmod

    with patch.object(runmod.Runner, "run", new=_fake_run):
        out = await _force_final_synthesis(_FakeAgent(), None, None)
    assert out == ""


async def test_never_raises_on_failure(monkeypatch):
    monkeypatch.delenv("KRYON_FINAL_SYNTHESIS", raising=False)

    async def _boom(a, *, input, max_turns, run_config):  # noqa: A002
        raise RuntimeError("model down")

    import kryon.sdk.agents.run as runmod

    with patch.object(runmod.Runner, "run", new=_boom):
        out = await _force_final_synthesis(_FakeAgent(), None, None)
    assert out == ""  # best-effort: swallow and return empty, never break the run
