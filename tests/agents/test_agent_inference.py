import os

import pytest

# Check if we have a real OpenAI API key (not a test/placeholder key, not Groq)
_api_key = os.environ.get("OPENAI_API_KEY", "")
_base_url = os.environ.get("OPENAI_BASE_URL", "")
_PLACEHOLDER_PREFIXES = ("test_key", "sk-placeholder", "sk-test", "not-set", "placeholder")
_is_placeholder = not _api_key or any(_api_key.startswith(p) for p in _PLACEHOLDER_PREFIXES)
_is_proxied = "groq.com" in _base_url or "localhost" in _base_url
_has_real_api_key = not _is_placeholder and not _is_proxied

# Set test environment variable if not already set to avoid import errors
if not _api_key:
    os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.agents import get_agent_by_name
from kryon.sdk.agents import Runner

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
    assert "run_command" in final_output.lower(), (
        f"Expected 'run_command' in output, got: {final_output}"
    )
    assert "nmap" in final_output.lower(), f"Expected 'nmap' in output, got: {final_output}"


async def test_red_team_agent_inference():
    """
    Non-streaming inference test for the pentest_agent.
    """
    prompt = "perform penetration test on example.com ssh service"
    result = await Runner.run(get_agent_by_name("pentest_agent"), prompt)
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
