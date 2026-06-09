"""The unified Kryon agent must ship with the security guardrails wired.

Regression for the gap where ``get_security_guardrails()`` existed but
``create_unified_agent()`` never passed them to the SDK ``Agent`` — the
production agent ran with no prompt-injection / scope / command-execution
protection at the SDK layer.
"""

from __future__ import annotations

import pytest

from kryon.skills.unified_agent import create_unified_agent


@pytest.mark.unit
def test_guardrails_wired_by_default(monkeypatch):
    monkeypatch.setenv("KRYON_GUARDRAILS", "true")
    agent = create_unified_agent()

    # 2 input guardrails (prompt-injection + scope), 1 output (command exec).
    assert len(agent.input_guardrails) >= 1
    assert len(agent.output_guardrails) >= 1


@pytest.mark.unit
def test_guardrails_opt_out(monkeypatch):
    monkeypatch.setenv("KRYON_GUARDRAILS", "false")
    agent = create_unified_agent()

    assert agent.input_guardrails == []
    assert agent.output_guardrails == []
