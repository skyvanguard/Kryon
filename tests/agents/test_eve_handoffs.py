"""Tests for exploit_validator (EVE) handoffs from central_core and vuln_hunter."""

import pytest


def test_central_core_has_exploit_validator_handoff():
    from kryon.agents.central_core import central_core

    assert central_core.handoffs, "central_core has no handoffs at all"
    handoff_names = []
    for h in central_core.handoffs:
        name = getattr(h, "agent_name", "") or getattr(h, "tool_name", "") or str(h)
        handoff_names.append(name.lower())
    assert any("exploit" in n or "validator" in n for n in handoff_names), (
        f"No exploit_validator handoff found in: {handoff_names}"
    )


def test_vuln_hunter_has_pentest_agent_handoff():
    """Vuln Hunter should hand off to Pentest Agent for exploitation (not exploit_validator)."""
    from kryon.agents.vuln_hunter import vuln_hunter

    assert vuln_hunter.handoffs, "vuln_hunter has no handoffs at all"
    handoff_names = []
    for h in vuln_hunter.handoffs:
        name = getattr(h, "agent_name", "") or getattr(h, "tool_name", "") or str(h)
        handoff_names.append(name.lower())
    assert any("pentest" in n for n in handoff_names), (
        f"No pentest_agent handoff found in: {handoff_names}"
    )
