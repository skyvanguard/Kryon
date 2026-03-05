"""Tests for the BAS Simulator agent definition."""

import pytest

from kryon.sdk.agents import FunctionTool


def test_bas_simulator_agent_exists():
    from kryon.agents.bas_simulator import bas_simulator

    assert bas_simulator is not None
    assert bas_simulator.name == "BAS Simulator"


def test_bas_simulator_has_core_tools():
    from kryon.agents.bas_simulator import bas_simulator

    tool_names = [t.name for t in bas_simulator.tools if isinstance(t, FunctionTool)]
    assert "run_command" in tool_names


def test_bas_simulator_has_bas_scenario_tools():
    from kryon.agents.bas_simulator import bas_simulator

    tool_names = [t.name for t in bas_simulator.tools if isinstance(t, FunctionTool)]
    assert "bas_endpoint_security" in tool_names
    assert "bas_data_exfiltration" in tool_names
    assert "bas_ad_reconnaissance" in tool_names
    assert "mitre_attack_mapping" in tool_names


def test_bas_simulator_has_attack_simulation_tools():
    from kryon.agents.bas_simulator import bas_simulator

    tool_names = [t.name for t in bas_simulator.tools if isinstance(t, FunctionTool)]
    assert "simulate_attack" in tool_names
    assert "validate_finding" in tool_names


def test_bas_simulator_has_instructions():
    from kryon.agents.bas_simulator import bas_simulator

    assert bas_simulator.instructions
    # instructions is a callable renderer; invoke it to get the actual prompt
    if callable(bas_simulator.instructions):
        rendered = bas_simulator.instructions()
        assert len(rendered) > 100
    else:
        assert len(str(bas_simulator.instructions)) > 100


def test_bas_simulator_description():
    from kryon.agents.bas_simulator import bas_simulator

    desc = bas_simulator.description.lower()
    assert "breach" in desc or "bas" in desc or "attack simulation" in desc


def test_transfer_function():
    from kryon.agents.bas_simulator import transfer_to_bas_simulator

    assert callable(transfer_to_bas_simulator)
    agent = transfer_to_bas_simulator()
    assert agent.name == "BAS Simulator"
