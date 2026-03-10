"""Tests for the AD Infiltrator agent definition."""

import pytest

from kryon.sdk.agents import FunctionTool


def test_ad_infiltrator_agent_exists():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    assert ad_infiltrator is not None
    assert ad_infiltrator.name == "AD Infiltrator"


def test_ad_infiltrator_has_ad_attack_tools():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [t.name for t in ad_infiltrator.tools if isinstance(t, FunctionTool)]
    assert "bloodhound_collect" in tool_names
    assert "kerberoast" in tool_names
    assert "asreproast" in tool_names
    assert "enumerate_ad" in tool_names
    assert "dcsync_attack" in tool_names
    assert "find_attack_path" in tool_names


def test_ad_infiltrator_has_pth_tools():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [t.name for t in ad_infiltrator.tools if isinstance(t, FunctionTool)]
    assert "pass_the_hash" in tool_names
    assert "pass_the_ticket" in tool_names


def test_ad_infiltrator_has_core_tools():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [t.name for t in ad_infiltrator.tools if isinstance(t, FunctionTool)]
    assert "run_command" in tool_names


def test_ad_infiltrator_has_validation_tool():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [t.name for t in ad_infiltrator.tools if isinstance(t, FunctionTool)]
    assert "validate_finding" in tool_names


def test_ad_infiltrator_has_instructions():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    assert ad_infiltrator.instructions
    # instructions is a callable renderer; invoke it to get the actual prompt
    if callable(ad_infiltrator.instructions):
        rendered = ad_infiltrator.instructions()
        assert len(rendered) > 100
    else:
        assert len(str(ad_infiltrator.instructions)) > 100


def test_ad_infiltrator_has_description():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    desc_lower = ad_infiltrator.description.lower()
    assert "active directory" in desc_lower or "ad " in desc_lower or "lateral movement" in desc_lower


def test_transfer_function_exists():
    from kryon.agents.ad_infiltrator import transfer_to_ad_infiltrator

    assert callable(transfer_to_ad_infiltrator)
    agent = transfer_to_ad_infiltrator()
    assert agent.name == "AD Infiltrator"
