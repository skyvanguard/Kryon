"""Tests for lazy_handoff utility."""

import pytest

from kryon.agents.lazy_handoff import (
    HANDOFF_BRIEFING_SCHEMA,
    ROUTER_HANDOFF_SCHEMA,
    lazy_handoff,
)
from kryon.sdk.agents.handoffs import Handoff


def test_lazy_handoff_returns_handoff_instance():
    """lazy_handoff() should return a Handoff dataclass."""
    h = lazy_handoff("recon_scout", "handoff_to_recon_scout", "Escalate to Recon Scout")
    assert isinstance(h, Handoff)
    assert h.tool_name == "handoff_to_recon_scout"
    assert h.tool_description == "Escalate to Recon Scout"
    assert h.agent_name == "recon_scout"


def test_lazy_handoff_default_schema_is_briefing():
    """lazy_handoff() should default to HANDOFF_BRIEFING_SCHEMA."""
    h = lazy_handoff("pentest_agent", "handoff_to_pentest", "Desc")
    assert h.input_json_schema == HANDOFF_BRIEFING_SCHEMA
    assert "findings_summary" in h.input_json_schema["properties"]
    assert "findings_summary" in h.input_json_schema["required"]


def test_lazy_handoff_custom_schema():
    """lazy_handoff() should accept a custom schema."""
    h = lazy_handoff("pentest_agent", "handoff_to_pentest", "Desc", schema=ROUTER_HANDOFF_SCHEMA)
    assert h.input_json_schema == ROUTER_HANDOFF_SCHEMA
    assert "task_description" in h.input_json_schema["properties"]
    assert "task_description" in h.input_json_schema["required"]


def test_lazy_handoff_strict_json_schema_disabled():
    """lazy_handoff() should set strict_json_schema=False for Ollama compatibility."""
    h = lazy_handoff("recon_scout", "handoff_to_recon_scout", "Desc")
    assert h.strict_json_schema is False


def test_handoff_briefing_schema_structure():
    """HANDOFF_BRIEFING_SCHEMA should have correct structure."""
    assert HANDOFF_BRIEFING_SCHEMA["type"] == "object"
    props = HANDOFF_BRIEFING_SCHEMA["properties"]
    assert "findings_summary" in props
    assert "recommended_action" in props
    assert HANDOFF_BRIEFING_SCHEMA["required"] == ["findings_summary"]
    assert HANDOFF_BRIEFING_SCHEMA["additionalProperties"] is False


def test_router_handoff_schema_structure():
    """ROUTER_HANDOFF_SCHEMA should have correct structure."""
    assert ROUTER_HANDOFF_SCHEMA["type"] == "object"
    props = ROUTER_HANDOFF_SCHEMA["properties"]
    assert "task_description" in props
    assert ROUTER_HANDOFF_SCHEMA["required"] == ["task_description"]
    assert ROUTER_HANDOFF_SCHEMA["additionalProperties"] is False


@pytest.mark.asyncio
async def test_lazy_handoff_resolves_agent_at_runtime():
    """on_invoke_handoff should resolve the agent by name at call time."""
    from unittest.mock import MagicMock

    h = lazy_handoff("recon_scout", "handoff_to_recon_scout", "Desc")
    ctx = MagicMock()
    ctx.context = None
    agent = await h.on_invoke_handoff(ctx, "")
    assert agent.name == "Recon Scout"
