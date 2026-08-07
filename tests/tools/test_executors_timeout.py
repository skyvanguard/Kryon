"""FASE 11.R — wall-clock timeout + process group kill in ``_run_local_async``.

The Bench Robots run (2026-05-27) hit a hang where a nikto pre_hook
spawned via ``run_command`` consumed its timeout but the
``async for line in process.stdout`` loop in ``_run_local_async``
never terminated. Reason: the perl ``nikto.pl`` child outlived the
shell parent (timeout killed the shell, child kept running orphaned)
and its stdout pipe was inherited by the orphan, so the readline
loop saw no EOF. ``asyncio.wait_for(process.wait(), timeout=timeout)``
on line 206 was unreachable.

Two invariants this file pins:

1. **Wall-clock timeout enforcement**: when the underlying command
   stops producing output but doesn't exit, the helper must still
   raise ``subprocess.TimeoutExpired`` within ~timeout seconds.
2. **Process group cleanup**: when timeout fires, every descendant
   of the spawned shell (not just the shell itself) must be killed,
   so we don't leak zombie ``perl`` / ``nikto`` / ``nmap`` children.

Both invariants apply in BOTH branches: streaming (the bench path)
and non-streaming (the parallel-mode path). The streaming branch is
the one that was broken; the non-streaming branch had the wall-clock
timeout but still leaked orphans.

Tests are gated POSIX-only — process groups + ``setsid`` don't exist
on Windows, and the bench container is Linux.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time

import pytest

from kryon.tools.common._executors import _run_local_async

POSIX_ONLY = pytest.mark.skipif(
    not hasattr(os, "setsid"),
    reason="Process group cleanup requires POSIX setsid (no Windows)",
)


# ---------------------------------------------------------------------------
# Wall-clock timeout — streaming branch
# ---------------------------------------------------------------------------


@POSIX_ONLY
@pytest.mark.asyncio
async def test_streaming_branch_returns_timeout_msg_on_silent_child(
    tmp_path,
) -> None:
    """The exact failure mode from Bench Robots: shell spawns a child,
    child holds the stdout pipe but writes nothing, shell would block
    forever on ``wait``. The internal raise is caught by the outer
    except, which returns a "timed out" string — the contract the
    agent loop expects. The fix's invariant is that this returns
    within ~timeout seconds, not hangs indefinitely."""
    # ``sleep`` inherits stdout but never writes. The shell exec's it
    # so the shell's own stdout is replaced by sleep's. Without the
    # wall-clock fix, the readline loop never sees EOF and the test
    # hangs until pytest-timeout (or forever).
    cmd = "exec sleep 10"
    start = time.monotonic()
    result = await _run_local_async(
        cmd,
        stdout=False,
        timeout=2,
        stream=True,
        workspace_dir=str(tmp_path),
    )
    elapsed = time.monotonic() - start
    # Generous upper bound — must fire within timeout + a small grace.
    # The bug case hung for 17 minutes; 6s catches any regression.
    assert elapsed < 6.0, f"timeout enforcement too slow: {elapsed:.2f}s"
    assert "timed out" in result.lower(), f"expected timeout msg, got: {result!r}"


@POSIX_ONLY
async def test_streaming_timeout_preserves_partial_output(tmp_path) -> None:
    """T3-A8: a tool that prints findings then hangs must return the PARTIAL output,
    not just 'timed out' — the model needs what nuclei/sqlmap found before the kill."""
    cmd = "sh -c 'echo PARTIAL_FINDING; exec sleep 10'"
    result = await _run_local_async(
        cmd,
        stdout=False,
        timeout=2,
        stream=True,
        workspace_dir=str(tmp_path),
    )
    assert "timed out" in result.lower()
    assert "PARTIAL_FINDING" in result  # partial output survived the timeout


@POSIX_ONLY
@pytest.mark.asyncio
async def test_streaming_branch_kills_grandchild_process(
    tmp_path,
) -> None:
    """Reproduce the nikto/perl orphan scenario: a shell spawns a
    long-running child whose pid we capture, fire the timeout, and
    verify the grandchild is no longer alive. Without process group
    kill, the shell dies but the grandchild lingers (Bench Robots
    scenario — perl PID 2976 with PPID=1 after shell got killed)."""
    # Run a shell that prints the child PID then waits. The child is
    # a backgrounded sleep so it has a stable pid we can poll.
    cmd = "exec sh -c 'sleep 30 & echo CHILD_PID=$!; exec sleep 30'"

    # Use a deep-helper: import the executor's hidden helper directly
    # via the module so we can capture the child pid from streaming
    # output. But _run_local_async doesn't expose output on timeout,
    # so instead we spawn the process ourselves and call the kill
    # helper — this asserts the helper kills the WHOLE group.
    from kryon.tools.common._executors import _kill_process_group

    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(tmp_path),
        start_new_session=True,
    )
    # Read the CHILD_PID line so we know the grandchild exists.
    line = await asyncio.wait_for(process.stdout.readline(), timeout=3)
    decoded = line.decode().strip()
    assert decoded.startswith("CHILD_PID="), f"unexpected output: {decoded!r}"
    grandchild_pid = int(decoded.split("=", 1)[1])

    # Confirm grandchild is alive before we fire.
    os.kill(grandchild_pid, 0)  # raises if dead

    _kill_process_group(process)
    # Give the kernel a moment to reap.
    await asyncio.wait_for(process.wait(), timeout=3)

    # Now the grandchild must be dead. ``os.kill(pid, 0)`` raises
    # ProcessLookupError when the pid no longer exists.
    with pytest.raises(ProcessLookupError):
        # Brief wait for reaper — kernel may take a few ms.
        for _ in range(20):
            os.kill(grandchild_pid, 0)
            await asyncio.sleep(0.05)


# ---------------------------------------------------------------------------
# Wall-clock timeout — non-streaming branch
# ---------------------------------------------------------------------------


@POSIX_ONLY
@pytest.mark.asyncio
async def test_nonstreaming_branch_returns_timeout_msg_on_silent_child(
    tmp_path,
) -> None:
    """Same hang fix applies in the parallel-mode (non-streaming)
    branch: ``asyncio.wait_for(communicate())`` already had a
    wall-clock, but the kill on timeout only hit the shell, not
    descendants. Confirm the timeout message is returned promptly."""
    cmd = "exec sleep 10"
    start = time.monotonic()
    result = await _run_local_async(
        cmd,
        stdout=False,
        timeout=2,
        stream=False,
        workspace_dir=str(tmp_path),
    )
    elapsed = time.monotonic() - start
    assert elapsed < 6.0, f"timeout enforcement too slow: {elapsed:.2f}s"
    assert "timed out" in result.lower(), f"expected timeout msg, got: {result!r}"


# ---------------------------------------------------------------------------
# Happy path — fix must not break normal output capture
# ---------------------------------------------------------------------------


@POSIX_ONLY
@pytest.mark.asyncio
async def test_streaming_branch_returns_output_on_success(tmp_path) -> None:
    """The wall-clock guard must not eat output on commands that
    finish well within timeout."""
    out = await _run_local_async(
        "echo hello-from-stream",
        stdout=False,
        timeout=5,
        stream=True,
        workspace_dir=str(tmp_path),
    )
    assert "hello-from-stream" in out


@POSIX_ONLY
@pytest.mark.asyncio
async def test_nonstreaming_branch_returns_output_on_success(tmp_path) -> None:
    out = await _run_local_async(
        "echo hello-no-stream",
        stdout=False,
        timeout=5,
        stream=False,
        workspace_dir=str(tmp_path),
    )
    assert "hello-no-stream" in out


# ---------------------------------------------------------------------------
# _kill_process_group helper — unit
# ---------------------------------------------------------------------------


@POSIX_ONLY
@pytest.mark.asyncio
async def test_kill_process_group_handles_already_exited_process(
    tmp_path,
) -> None:
    """If the process already exited before the kill helper runs
    (race between wait and kill), the helper must NOT raise."""
    from kryon.tools.common._executors import _kill_process_group

    process = await asyncio.create_subprocess_shell(
        "true",
        cwd=str(tmp_path),
        start_new_session=True,
    )
    await process.wait()  # process is dead before we call kill
    # Must not raise.
    _kill_process_group(process)
