"""Fixture for python-hatch pre_hook tests.

Each callable below is exercised by tests/skills/test_pre_hook_runner.py
to validate the Fase 5 escape hatch (`python: ./<file>.py:<func>`).

Contract: a python hook receives `ctx: dict[str, Any]` and returns
`str | dict | list`. The runner coerces non-strings to JSON / repr.
"""

from __future__ import annotations

import asyncio
from typing import Any


def run_sync(ctx: dict[str, Any]) -> str:
    host = ctx.get("host", "")
    return f"sync hook saw host={host!r}"


async def run_async(ctx: dict[str, Any]) -> str:
    await asyncio.sleep(0.01)
    return f"async hook ssh_user={ctx.get('ssh_user', '')!r}"


def returns_dict(ctx: dict[str, Any]) -> dict[str, Any]:
    return {"verdicts": {"PASS": 5, "FAIL": 2}, "host": ctx.get("host", "")}


def fails(ctx: dict[str, Any]) -> str:
    raise RuntimeError("expected failure for tests")


async def slow(ctx: dict[str, Any]) -> str:
    await asyncio.sleep(2)
    return "should never reach this"


# Intentionally NOT callable — used to test the "not callable" error path.
not_a_function: int = 42
