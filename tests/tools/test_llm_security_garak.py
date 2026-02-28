"""Tests for llm_security.garak_wrapper — Garak LLM vulnerability scanner."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.llm_security.garak_wrapper import garak_scan, garak_list_probes


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# garak_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_default(monkeypatch):
    """Default scan uses all probes and detectors."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "Scan complete: 0 vulnerabilities"

    monkeypatch.setattr("kryon.tools.llm_security.garak_wrapper.run_command", fake_run)

    result = await _invoke(garak_scan, {"target_model": "openai:gpt-4"})
    assert "garak" in captured["cmd"]
    assert "--model_type openai" in captured["cmd"]
    assert "--model_name gpt-4" in captured["cmd"]
    assert "--generations 5" in captured["cmd"]
    # "all" probes should NOT add --probes flag
    assert "--probes" not in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_specific_probes(monkeypatch):
    """Specific probes are forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "results"

    monkeypatch.setattr("kryon.tools.llm_security.garak_wrapper.run_command", fake_run)

    result = await _invoke(garak_scan, {
        "target_model": "openai:gpt-4",
        "probes": "promptinject,encoding",
    })
    assert "--probes promptinject,encoding" in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_custom_model(monkeypatch):
    """Custom model identifier is parsed correctly."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "results"

    monkeypatch.setattr("kryon.tools.llm_security.garak_wrapper.run_command", fake_run)

    result = await _invoke(garak_scan, {
        "target_model": "huggingface:meta-llama/Llama-2-7b",
    })
    assert "--model_type huggingface" in captured["cmd"]
    assert "--model_name meta-llama/Llama-2-7b" in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_custom_generations(monkeypatch):
    """Custom generations count is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "results"

    monkeypatch.setattr("kryon.tools.llm_security.garak_wrapper.run_command", fake_run)

    result = await _invoke(garak_scan, {
        "target_model": "openai:gpt-4",
        "generations": 20,
    })
    assert "--generations 20" in captured["cmd"]


@pytest.mark.asyncio
async def test_scan_model_without_colon(monkeypatch):
    """Model without colon defaults to openai type."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "results"

    monkeypatch.setattr("kryon.tools.llm_security.garak_wrapper.run_command", fake_run)

    result = await _invoke(garak_scan, {"target_model": "gpt-4-turbo"})
    assert "--model_type openai" in captured["cmd"]
    assert "--model_name gpt-4-turbo" in captured["cmd"]


# ---------------------------------------------------------------------------
# garak_list_probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_probes(monkeypatch):
    """List probes runs garak --list_probes."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "promptinject\nencoding\ndan\nglitch"

    monkeypatch.setattr("kryon.tools.llm_security.garak_wrapper.run_command", fake_run)

    result = await _invoke(garak_list_probes, {})
    assert "garak --list_probes" in captured["cmd"]
    assert "promptinject" in result
