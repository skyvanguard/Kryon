"""
Claude Code CLI integration tool.

Delegates complex tasks (script writing, deep analysis, exploit generation,
report creation) to Claude Code CLI, which uses the user's Claude Pro Max
subscription.  The local Ollama model handles simple tasks while claude_code
handles anything requiring advanced reasoning.
"""

import asyncio
import json
import logging
import os
import subprocess

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


@function_tool
async def claude_code(
    task: str,
    model: str = "sonnet",
    save_to_file: str = "",
) -> str:
    """Delegate a complex task to Claude Code CLI (uses Claude Pro Max subscription).

    Use this tool for tasks that require advanced reasoning:
    - Writing scripts, exploits, or complex code
    - Deep analysis of scan results or vulnerabilities
    - Generating detailed reports or documentation
    - Complex problem solving that exceeds local model capabilities
    - Analyzing large amounts of data or logs

    For simple tasks (running commands, basic queries), use run_command instead.

    Args:
        task: Detailed description of what Claude should do.
        model: Claude model to use — "sonnet" (default, fast), "opus" (best quality), "haiku" (fastest).
        save_to_file: Optional file path to save the output to.

    Returns:
        Claude's response text with the completed task.
    """
    if not task or not task.strip():
        return "Error: task cannot be empty."

    allowed_models = {"sonnet", "opus", "haiku"}
    if model not in allowed_models:
        return f"Error: model must be one of {allowed_models}, got '{model}'."

    cmd = ["claude", "-p", "--output-format", "json", "--model", model]

    def _run():
        try:
            result = subprocess.run(
                cmd,
                input=task,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout: Claude Code did not respond within 300 seconds.", -1
        except FileNotFoundError:
            return (
                "",
                "Claude Code CLI not found. Install with: npm install -g @anthropic-ai/claude-code",
                -1,
            )

    stdout, stderr, returncode = await asyncio.to_thread(_run)

    if returncode != 0:
        logger.warning("claude_code failed (rc=%d): %s", returncode, stderr)
        return f"Error (exit {returncode}): {stderr}"

    # Parse JSON response from Claude CLI
    try:
        data = json.loads(stdout)
        text = data.get("result", str(data))
    except (json.JSONDecodeError, TypeError):
        text = stdout

    if not text:
        return "Error: Claude Code returned an empty response."

    # Optionally save to file
    if save_to_file:
        try:
            workspace = os.path.realpath(os.getcwd())
            resolved = os.path.realpath(save_to_file)
            if not resolved.startswith(workspace + os.sep) and resolved != workspace:
                return "Error: save_to_file must be within the current workspace directory."
            os.makedirs(os.path.dirname(resolved) or ".", exist_ok=True)
            with open(resolved, "w", encoding="utf-8") as f:
                f.write(text)
            text += f"\n\n[Output saved to {save_to_file}]"
        except OSError as exc:
            text += f"\n\n[Warning: could not save to {save_to_file}: {exc}]"

    return text
