import os

import pytest

# Check if we have a real API key (not the test placeholder)
_api_key = os.environ.get("OPENAI_API_KEY", "")
_has_real_api_key = _api_key and not _api_key.startswith("test_key")

# Set test environment variable if not already set to avoid import errors
if not _api_key:
    os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from skynet.agents import get_agent_by_name
from skynet.sdk.agents import Runner

# Skip all tests in this module if no real API key is available
pytestmark = [
    pytest.mark.skipif(not _has_real_api_key, reason="Requires real OPENAI_API_KEY for inference tests"),
    pytest.mark.allow_call_model_methods,
    pytest.mark.asyncio,
]


async def test_blue_team_agent_inference():
    """
    Non-streaming inference test for the blue_teamer agent.
    """
    prompt = "Monitor login attempts for suspicious activity what we can do?"
    result = await Runner.run(get_agent_by_name("blue_teamer"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "login" in final_output.lower(), f"Expected 'login' in output, got: {final_output}"


async def test_bug_bounter_agent_inference():
    """
    Non-streaming inference test for the bug_bounter agent.
    """
    prompt = "Find vulnerabilities in web application sample.com"
    result = await Runner.run(get_agent_by_name("bug_bounter"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "sample.com" in final_output.lower(), f"Expected 'sample.com' in output, got: {final_output}"


async def test_dns_smtp_agent_inference():
    """
    Non-streaming inference test for the dns_smtp_agent.
    """
    prompt = "check DKIM record for example.com"
    result = await Runner.run(get_agent_by_name("dns_smtp_agent"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "dkim" in final_output.lower(), f"Expected 'dkim' in output, got: {final_output}"


async def test_one_tool_agent_inference():
    """
    Non-streaming inference test for the one_tool_agent.
    """
    prompt = "use nmap to scan 192.168.3.0/24"
    result = await Runner.run(get_agent_by_name("one_tool_agent"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "generic_linux_command" in final_output.lower(), (
        f"Expected 'generic_linux_command' in output, got: {final_output}"
    )
    assert "nmap" in final_output.lower(), f"Expected 'nmap' in output, got: {final_output}"


async def test_red_team_agent_inference():
    """
    Non-streaming inference test for the t800_infiltrator agent.
    """
    prompt = "perform penetration test on example.com ssh service"
    result = await Runner.run(get_agent_by_name("t800_infiltrator"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "example.com" in final_output.lower(), f"Expected 'example.com' in output, got: {final_output}"


async def test_flag_discriminator_inference():
    """
    Non-streaming inference test for the flag_discriminator agent.
    """
    prompt = "Hello! Can you find tell me which is the flag in this string: 'Hi there, your reward flag{1234}"
    result = await Runner.run(get_agent_by_name("flag_discriminator"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "flag{1234}" in final_output.lower(), f"Expected 'flag{1234}' in output, got: {final_output}"


async def test_thought_agent_inference():
    """
    Non-streaming inference test for the thought agent.
    """
    prompt = """The phases of the cybersecurity kill chain are:
    Reconnaissance, Exploitation, Lateral Movement, Data Exfiltration, and Command and Control (C2).
    In which phase of the kill chain does this example fall:
    Gathering initial intelligence about the target using OSINT techniques?"""
    result = await Runner.run(get_agent_by_name("thought"), prompt)
    final_output = result.final_output or ""
    assert final_output, "Expected non-empty final output"
    assert "reconnaissance" in final_output.lower(), f"Expected 'reconnaissance' in output, got: {final_output}"
