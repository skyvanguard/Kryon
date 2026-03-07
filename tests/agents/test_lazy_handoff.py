"""Tests for lazy_handoff utility."""

import pytest

from kryon.agents.lazy_handoff import lazy_handoff
from kryon.sdk.agents.handoffs import Handoff


def test_lazy_handoff_returns_handoff_instance():
    """lazy_handoff() should return a Handoff dataclass."""
    h = lazy_handoff("recon_scout", "handoff_to_recon_scout", "Escalate to Recon Scout")
    assert isinstance(h, Handoff)
    assert h.tool_name == "handoff_to_recon_scout"
    assert h.tool_description == "Escalate to Recon Scout"
    assert h.agent_name == "recon_scout"


def test_lazy_handoff_has_empty_schema():
    """lazy_handoff() should have empty input schema (no args needed)."""
    h = lazy_handoff("pentest_agent", "handoff_to_pentest", "Desc")
    assert h.input_json_schema == {}


@pytest.mark.asyncio
async def test_lazy_handoff_resolves_agent_at_runtime():
    """on_invoke_handoff should resolve the agent by name at call time."""
    from unittest.mock import MagicMock

    h = lazy_handoff("recon_scout", "handoff_to_recon_scout", "Desc")
    ctx = MagicMock()
    ctx.context = None
    agent = await h.on_invoke_handoff(ctx, "")
    assert agent.name == "Recon Scout"
