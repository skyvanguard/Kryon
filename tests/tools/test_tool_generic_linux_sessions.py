import json
import os
import re
import sys

import pytest

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.reconnaissance.run_command import run_command


def _extract_alias(msg: str) -> str | None:
    m = re.search(r"Started async session\s+(S\d+)", msg)
    return m.group(1) if m else None


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="Uses Unix-specific commands (sh, cat)")
async def test_interactive_session_create_and_io():
    # Create a simple interactive session that emits one line then echoes stdin
    cmd = "sh -c 'printf ready\\n; cat -'"
    args = {"command": cmd, "interactive": True}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "Started async session" in out

    alias = _extract_alias(out)
    assert alias is not None

    # Read initial output (should contain 'ready')
    args = {"command": f"output {alias}"}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "ready" in out or "Started" in out

    # Send a line and expect to see it echoed back by cat -
    args = {"command": "hello-world", "session_id": alias}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "hello-world" in out

    # Kill the session
    args = {"command": f"kill {alias}"}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert "terminated" in out.lower() or "already terminated" in out.lower()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="Uses Unix-specific commands (sh, cat)")
async def test_session_parsing_variants():
    # New interactive session
    cmd = "sh -c 'printf ready\\n; cat -'"
    args = {"command": cmd, "interactive": True}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    alias = _extract_alias(out)
    assert alias is not None

    # Old variant: command="session", session_id="output S#"
    args = {"command": "session", "session_id": f"output {alias}"}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert isinstance(out, str)
    assert "Session" not in out or "not found" not in out

    # status should return a string even if no new output
    args = {"command": f"status {alias}"}
    out = await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(args))
    assert isinstance(out, str)

    # Cleanup
    await run_command.on_invoke_tool(RunContextWrapper(None), json.dumps({"command": f"kill {alias}"}))
