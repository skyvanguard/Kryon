"""Regression: create_unified_agent must honor model_override.

The param was declared but never wired to create_agent(), so /parallel
multi-model comparison and the TUI model selector silently ran every agent
on KRYON_MODEL — the "different" models were identical.
"""

from __future__ import annotations

from kryon.skills.unified_agent import create_unified_agent

_SENTINEL = "sentinel-override-model-xyz"


def test_model_override_is_wired_to_the_agent() -> None:
    agent = create_unified_agent(user_msg="recon quick", model_override=_SENTINEL, agent_id="P2")
    assert str(agent.model.model) == _SENTINEL
    assert agent._agent_id == "P2"


def test_without_override_falls_back_to_default_model() -> None:
    agent = create_unified_agent(user_msg="recon quick")
    assert str(agent.model.model) != _SENTINEL
    assert agent._agent_id is None
