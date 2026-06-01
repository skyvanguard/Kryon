"""Tests for per-pre_hook timeout + orphan-subprocess kill."""

from __future__ import annotations

import os
import time

import pytest

from kryon.skills.pre_hook_runner import (
    PreHookExecutionError,
    _all_descendants,
    _invoke_one,
    _kill_pids,
)
from kryon.skills.pre_hook_spec import PreHookSpec


def _slow_tool(**kwargs):
    """Simulates a hung subprocess-backed tool (nuclei/sqlmap)."""
    time.sleep(3)
    return "done"


async def test_sync_hook_times_out_fast():
    """A blocking sync hook must time out at timeout_s, not run to completion.

    This is the regression for the 100%-CPU hang: before, wait_for raised but
    the executor thread kept the call alive; here we assert the runner returns
    control promptly with a timeout error.
    """
    hook = PreHookSpec(tool="slow", timeout_s=1)
    start = time.monotonic()
    with pytest.raises(PreHookExecutionError, match="timed out"):
        await _invoke_one(hook, {}, {"slow": _slow_tool})
    assert time.monotonic() - start < 8  # honored ~1s, did not wait 30s


def test_kill_pids_safe_on_bogus():
    _kill_pids({999_999_999})  # must not raise


def test_all_descendants_returns_set():
    assert isinstance(_all_descendants(os.getpid()), set)
