"""Async command execution helper for subprocess-based tools.

Usage pattern — migrate sync _run_cmd() calls::

    # Before (blocking):
    def _run_cmd(command: str, timeout: int = 120) -> str:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr

    # After (non-blocking):
    from kryon.tools.common._async_cmd import run_cmd_async

    async def my_tool(...):
        output = await run_cmd_async(command, timeout=120)
"""

from __future__ import annotations

import asyncio
import subprocess  # nosec B404


async def run_cmd_async(
    command: str | list[str],
    *,
    timeout: int = 300,
    shell: bool = True,
) -> str:
    """Run a subprocess command without blocking the event loop.

    Wraps ``subprocess.run()`` in ``asyncio.to_thread()`` so it
    executes in a thread pool while other async tasks continue.

    Args:
        command: Shell command string or list of args.
        timeout: Maximum seconds before killing the process.
        shell: Whether to run through the shell (default True for string commands).

    Returns:
        Combined stdout + stderr as a string.
    """
    try:
        result = await asyncio.to_thread(
            subprocess.run,  # nosec B602
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout or ""
        if result.stderr:
            output += "\n" + result.stderr
        return output.strip()
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"
