import json
import os
import sys

import pytest

# Set test environment variables to avoid OpenAI client initialization errors
os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.reconnaissance.run_command import run_command


@pytest.mark.asyncio
async def test_run_command_echo():
    """Test the execution of echo command using run_command."""
    # Use different command syntax for Windows vs Linux
    if sys.platform == "win32":
        args = {"command": "echo hello"}
        expected = "hello"
    else:
        args = {"command": "echo 'hello'"}
        expected = "hello"
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert expected in result.strip()


@pytest.mark.asyncio
async def test_run_command_ls():
    """Test the execution of ls command using run_command."""
    args = {"command": "ls -l"}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    # Check that the output contains typical ls -l indicators
    assert "total" in result or "drwx" in result or "-rw" in result


@pytest.mark.asyncio
async def test_run_command_invalid_command():
    """Test handling of invalid command using run_command."""
    args = {"command": "invalid_command_xyz123"}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    # Check for common error indicators (including Windows localized messages)
    result_lower = result.lower()
    error_indicators = [
        "not found",
        "command not found",
        "no such file",
        "not recognized",  # English Windows ("is not recognized as an internal or external command")
        "no se reconoce",  # Spanish Windows
        "wird nicht erkannt",  # German Windows
        "n'est pas reconnu",  # French Windows
        "exited with code",  # Generic exit code indicator
    ]
    assert any(indicator in result_lower for indicator in error_indicators), f"Expected error indicator in: {result}"


@pytest.mark.asyncio
async def test_run_command_empty_command():
    """Test handling of empty command using run_command."""
    args = {"command": ""}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "Error: No command provided" in result


@pytest.mark.asyncio
async def test_run_command_session_list():
    """Test session list functionality using run_command."""
    args = {"command": "session list"}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "No active sessions" in result or "Active sessions:" in result


@pytest.mark.asyncio
async def test_run_command_env_info():
    """Test environment info functionality using run_command."""
    args = {"command": "env info"}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "Current Environment:" in result
    assert "CTF Environment:" in result
    assert "Container:" in result
    assert "SSH:" in result
    assert "Workspace:" in result


@pytest.mark.asyncio
async def test_run_command_interactive_flag():
    """Test interactive flag functionality using run_command."""
    # Test with interactive=True but a simple command
    args = {"command": "echo 'test'", "interactive": True}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    # Should still work, just might have different session handling
    assert "test" in result


@pytest.mark.asyncio
async def test_run_command_with_session_id():
    """Test session_id parameter using run_command."""
    # Test with a non-existent session_id
    args = {"command": "echo 'test'", "session_id": "nonexistent123"}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    # Should handle gracefully - either execute or give session error
    assert isinstance(result, str)


@pytest.mark.asyncio
@pytest.mark.parametrize("sentinel", ["null", "none", "None", "NULL", "", "undefined", "n/a"])
async def test_run_command_sentinel_session_id_runs_stateless(sentinel):
    """Regression: LLMs emit the literal string 'null'/'none'/'' for an unset
    session_id. A truthy 'null' used to route into the session-send branch and
    return 'Session null not found', which made the model loop (dev.cashbox run,
    2026-07-18). The sentinel must be normalized to None so the command runs
    stateless — output present, and NOT a 'not found' session error.
    """
    cmd = "echo hello" if sys.platform == "win32" else "echo 'hello'"
    args = {"command": cmd, "session_id": sentinel}
    result = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "hello" in result
    assert "not found" not in result.lower()
