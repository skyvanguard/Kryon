"""Tests for the API Fuzzer agent definition."""

import pytest

from kryon.sdk.agents import FunctionTool


def test_api_fuzzer_agent_exists():
    from kryon.agents.api_fuzzer import api_fuzzer

    assert api_fuzzer is not None
    assert api_fuzzer.name == "API Fuzzer"


def test_api_fuzzer_has_tools():
    from kryon.agents.api_fuzzer import api_fuzzer

    tool_names = [t.name for t in api_fuzzer.tools if isinstance(t, FunctionTool)]
    assert "run_command" in tool_names
    # API fuzzer specific tools
    assert "parse_openapi_spec" in tool_names
    assert "discover_api_endpoints" in tool_names
    assert "fuzz_api_endpoint" in tool_names
    assert "test_idor" in tool_names


def test_api_fuzzer_has_rate_limiting_tool():
    from kryon.agents.api_fuzzer import api_fuzzer

    tool_names = [t.name for t in api_fuzzer.tools if isinstance(t, FunctionTool)]
    assert "test_rate_limiting" in tool_names


def test_api_fuzzer_has_auth_mechanisms_tool():
    from kryon.agents.api_fuzzer import api_fuzzer

    tool_names = [t.name for t in api_fuzzer.tools if isinstance(t, FunctionTool)]
    assert "test_auth_mechanisms" in tool_names


def test_api_fuzzer_has_validate_finding_tool():
    from kryon.agents.api_fuzzer import api_fuzzer

    tool_names = [t.name for t in api_fuzzer.tools if isinstance(t, FunctionTool)]
    assert "validate_finding" in tool_names


def test_api_fuzzer_has_instructions():
    from kryon.agents.api_fuzzer import api_fuzzer

    assert api_fuzzer.instructions
    # instructions is a callable renderer; invoke it to get the actual prompt
    if callable(api_fuzzer.instructions):
        rendered = api_fuzzer.instructions()
        assert len(rendered) > 100
    else:
        assert len(str(api_fuzzer.instructions)) > 100


def test_api_fuzzer_description():
    from kryon.agents.api_fuzzer import api_fuzzer

    desc = api_fuzzer.description.lower()
    assert "api" in desc


def test_transfer_function():
    from kryon.agents.api_fuzzer import transfer_to_api_fuzzer

    assert callable(transfer_to_api_fuzzer)
    agent = transfer_to_api_fuzzer()
    assert agent.name == "API Fuzzer"
