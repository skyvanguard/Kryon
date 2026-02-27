"""Tests for the claude_code tool — Claude Code CLI integration."""

import json
import os

import pytest

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.ai.claude_code import claude_code


def _invoke(args: dict):
    """Helper to invoke claude_code via on_invoke_tool."""
    return claude_code.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_task():
    """Empty task should return an error, not call subprocess."""
    result = await _invoke({"task": ""})
    assert "Error" in result
    assert "empty" in result.lower()


@pytest.mark.asyncio
async def test_whitespace_only_task():
    """Whitespace-only task should return an error."""
    result = await _invoke({"task": "   "})
    assert "Error" in result


@pytest.mark.asyncio
async def test_invalid_model():
    """Invalid model name should return an error before calling subprocess."""
    result = await _invoke({"task": "hello", "model": "gpt-99"})
    assert "Error" in result
    assert "model" in result.lower()


# ---------------------------------------------------------------------------
# CLI not found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cli_not_found(monkeypatch):
    """When 'claude' binary is missing, return a helpful error."""
    import subprocess as sp

    original_run = sp.run

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("claude not found")

    monkeypatch.setattr(sp, "run", fake_run)

    result = await _invoke({"task": "write a hello world script"})
    assert "Claude Code CLI not found" in result


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeout(monkeypatch):
    """Subprocess timeout should be caught gracefully."""
    import subprocess as sp

    def fake_run(*args, **kwargs):
        raise sp.TimeoutExpired(cmd="claude", timeout=300)

    monkeypatch.setattr(sp, "run", fake_run)

    result = await _invoke({"task": "complex analysis task"})
    assert "Timeout" in result


# ---------------------------------------------------------------------------
# Non-zero exit code
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nonzero_exit(monkeypatch):
    """Non-zero exit code should surface stderr."""
    import subprocess as sp

    def fake_run(*args, **kwargs):
        return sp.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="Authentication failed",
        )

    monkeypatch.setattr(sp, "run", fake_run)

    result = await _invoke({"task": "do something"})
    assert "Error" in result
    assert "Authentication failed" in result


# ---------------------------------------------------------------------------
# JSON response parsing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_json_response(monkeypatch):
    """Claude CLI JSON output should be parsed and the 'result' key extracted."""
    import subprocess as sp

    payload = json.dumps({"result": "Here is your exploit code..."})

    def fake_run(*args, **kwargs):
        return sp.CompletedProcess(
            args=args[0], returncode=0, stdout=payload, stderr=""
        )

    monkeypatch.setattr(sp, "run", fake_run)

    result = await _invoke({"task": "write an exploit"})
    assert "Here is your exploit code..." in result


@pytest.mark.asyncio
async def test_plain_text_response(monkeypatch):
    """Non-JSON stdout should be returned as-is."""
    import subprocess as sp

    def fake_run(*args, **kwargs):
        return sp.CompletedProcess(
            args=args[0], returncode=0, stdout="plain text answer", stderr=""
        )

    monkeypatch.setattr(sp, "run", fake_run)

    result = await _invoke({"task": "simple question"})
    assert "plain text answer" in result


@pytest.mark.asyncio
async def test_empty_response(monkeypatch):
    """Empty stdout should return an error message."""
    import subprocess as sp

    def fake_run(*args, **kwargs):
        return sp.CompletedProcess(
            args=args[0], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(sp, "run", fake_run)

    result = await _invoke({"task": "do something"})
    assert "empty response" in result.lower()


# ---------------------------------------------------------------------------
# save_to_file
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_to_file(monkeypatch, tmp_path):
    """save_to_file should write output to disk."""
    import subprocess as sp

    payload = json.dumps({"result": "saved content"})

    def fake_run(*args, **kwargs):
        return sp.CompletedProcess(
            args=args[0], returncode=0, stdout=payload, stderr=""
        )

    monkeypatch.setattr(sp, "run", fake_run)

    out_file = str(tmp_path / "subdir" / "output.txt")
    result = await _invoke(
        {"task": "generate report", "save_to_file": out_file}
    )
    assert os.path.exists(out_file)
    with open(out_file, encoding="utf-8") as f:
        assert "saved content" in f.read()
    assert f"[Output saved to {out_file}]" in result


@pytest.mark.asyncio
async def test_save_to_file_error(monkeypatch, tmp_path):
    """Failure to write file should warn but not lose the response text."""
    import subprocess as sp

    payload = json.dumps({"result": "important data"})

    def fake_run(*args, **kwargs):
        return sp.CompletedProcess(
            args=args[0], returncode=0, stdout=payload, stderr=""
        )

    monkeypatch.setattr(sp, "run", fake_run)

    # Monkeypatch open to simulate OSError on write
    original_open = open

    def broken_open(path, *args, **kwargs):
        if "broken_output" in str(path):
            raise OSError("Permission denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", broken_open)

    bad_path = str(tmp_path / "broken_output.txt")
    result = await _invoke({"task": "x", "save_to_file": bad_path})
    assert "important data" in result
    assert "Warning" in result


# ---------------------------------------------------------------------------
# Model parameter forwarding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_model_parameter_forwarded(monkeypatch):
    """The model parameter should appear in the subprocess command."""
    import subprocess as sp

    captured_cmd = []

    def fake_run(cmd, *args, **kwargs):
        captured_cmd.extend(cmd)
        return sp.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps({"result": "ok"}),
            stderr="",
        )

    monkeypatch.setattr(sp, "run", fake_run)

    await _invoke({"task": "test", "model": "opus"})
    assert "opus" in captured_cmd


@pytest.mark.asyncio
async def test_default_model_is_sonnet(monkeypatch):
    """Default model should be sonnet when not specified."""
    import subprocess as sp

    captured_cmd = []

    def fake_run(cmd, *args, **kwargs):
        captured_cmd.extend(cmd)
        return sp.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps({"result": "ok"}),
            stderr="",
        )

    monkeypatch.setattr(sp, "run", fake_run)

    await _invoke({"task": "test"})
    assert "sonnet" in captured_cmd
