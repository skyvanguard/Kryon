"""Tests for llm_security.prompt_injection — prompt injection testing tools."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.llm_security.prompt_injection import (
    generate_injection_payloads,
    test_data_extraction,
    test_prompt_injection,
)


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# test_prompt_injection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_injection_all_types(monkeypatch):
    """All injection types sends payloads from all categories."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return '{"response": "I cannot do that"}'

    monkeypatch.setattr("kryon.tools.llm_security.prompt_injection.run_command", fake_run)

    result = await _invoke(
        test_prompt_injection,
        {
            "target_url": "https://llm.example.com/v1/chat",
        },
    )
    assert "Prompt Injection Test" in result
    assert len(calls) > 0
    # Should include payloads from multiple categories
    assert "jailbreak" in result or "system_prompt_leak" in result


@pytest.mark.asyncio
async def test_injection_jailbreak_only(monkeypatch):
    """Jailbreak-only injection sends only jailbreak payloads."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return '{"response": "blocked"}'

    monkeypatch.setattr("kryon.tools.llm_security.prompt_injection.run_command", fake_run)

    result = await _invoke(
        test_prompt_injection,
        {
            "target_url": "https://llm.example.com/v1/chat",
            "injection_type": "jailbreak",
        },
    )
    assert "jailbreak" in result.lower()
    # Should have 5 jailbreak payloads
    assert len(calls) == 5


@pytest.mark.asyncio
async def test_injection_max_payloads(monkeypatch):
    """max_payloads limits the number of tests."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return '{"response": "ok"}'

    monkeypatch.setattr("kryon.tools.llm_security.prompt_injection.run_command", fake_run)

    result = await _invoke(
        test_prompt_injection,
        {
            "target_url": "https://llm.example.com/v1/chat",
            "injection_type": "all",
            "max_payloads": 3,
        },
    )
    assert len(calls) == 3


# ---------------------------------------------------------------------------
# generate_injection_payloads
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_payloads_jailbreak():
    """Jailbreak payloads include DAN-style prompts."""
    result = await _invoke(
        generate_injection_payloads,
        {
            "injection_type": "jailbreak",
        },
    )
    payloads = result.strip().split("\n")
    assert len(payloads) > 0
    # Should include base payloads + variations
    assert any("DAN" in p or "unrestricted" in p.lower() for p in payloads)


@pytest.mark.asyncio
async def test_generate_payloads_system_prompt_leak():
    """System prompt leak payloads target system prompt extraction."""
    result = await _invoke(
        generate_injection_payloads,
        {
            "injection_type": "system_prompt_leak",
        },
    )
    payloads = result.strip().split("\n")
    assert len(payloads) > 0
    assert any("system prompt" in p.lower() or "instructions" in p.lower() for p in payloads)


@pytest.mark.asyncio
async def test_generate_payloads_count():
    """Count parameter limits number of generated payloads."""
    result = await _invoke(
        generate_injection_payloads,
        {
            "injection_type": "jailbreak",
            "count": 3,
        },
    )
    payloads = result.strip().split("\n")
    assert len(payloads) <= 3


# ---------------------------------------------------------------------------
# test_data_extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_data_extraction_default(monkeypatch):
    """Data extraction test sends extraction prompts."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return '{"response": "I cannot share that"}'

    monkeypatch.setattr("kryon.tools.llm_security.prompt_injection.run_command", fake_run)

    result = await _invoke(
        test_data_extraction,
        {
            "target_url": "https://llm.example.com/v1/chat",
        },
    )
    assert "Data Extraction Test" in result
    assert len(calls) > 0


@pytest.mark.asyncio
async def test_data_extraction_with_hint(monkeypatch):
    """System prompt hint parameter is accepted."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return '{"response": "no"}'

    monkeypatch.setattr("kryon.tools.llm_security.prompt_injection.run_command", fake_run)

    result = await _invoke(
        test_data_extraction,
        {
            "target_url": "https://llm.example.com/v1/chat",
            "system_prompt_hint": "You are a helpful assistant",
        },
    )
    assert "Data Extraction Test" in result
    assert len(calls) > 0
