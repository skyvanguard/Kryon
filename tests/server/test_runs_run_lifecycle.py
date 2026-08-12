"""Streamed-run lifecycle: the ``running`` status transition (#2) and the
wall-clock backstop that stops an abandoned/stuck run from hogging the model
backend forever (#3).

The reflective loop is stubbed so no GPU/network is needed; the route's task
plumbing (status transitions + ``asyncio.wait_for`` cap) is real. The polling
tests lift the per-endpoint ``/api/v1/runs/`` rate limit (a hard 15-rpm bucket
override) so status can be sampled quickly without tripping it.
"""

from __future__ import annotations

import asyncio
import time
import types

import pytest

from kryon.server.routes.runs import _run_wall_cap_s


@pytest.fixture
def _lift_runs_ratelimit(monkeypatch):
    """Raise the hard 15-rpm cap on the ``/api/v1/runs/`` bucket so the status
    pollers below don't 429. The middleware reads this module dict per request."""
    from kryon.server.middleware.rate_limit import _ENDPOINT_LIMITS

    monkeypatch.setitem(_ENDPOINT_LIMITS, "/api/v1/runs/", 1_000_000)


def _post_rich(client, **over):
    body = {
        "agent_key": "kryon",
        "input": "hola",
        "stream": True,
        "rich_events": True,
        "free_run": True,  # isolate the reflective loop (no determinism / network)
        "max_turns": 3,
    }
    body.update(over)
    r = client.post("/api/v1/runs", json=body)
    assert r.status_code == 200
    return r.json()["run_id"]


def _status(client, run_id):
    return client.get(f"/api/v1/runs/{run_id}").json()["status"]


def _wait_status(client, run_id, targets, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = _status(client, run_id)
        if st in targets:
            return st
        time.sleep(0.03)
    return _status(client, run_id)


# --- #3: wall-cap env parsing ---


def test_wall_cap_default(monkeypatch):
    monkeypatch.delenv("KRYON_RUN_MAX_WALL_S", raising=False)
    assert _run_wall_cap_s() == 3600.0


def test_wall_cap_custom(monkeypatch):
    monkeypatch.setenv("KRYON_RUN_MAX_WALL_S", "120")
    assert _run_wall_cap_s() == 120.0


def test_wall_cap_zero_disables(monkeypatch):
    monkeypatch.setenv("KRYON_RUN_MAX_WALL_S", "0")
    assert _run_wall_cap_s() is None


def test_wall_cap_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("KRYON_RUN_MAX_WALL_S", "not-a-number")
    assert _run_wall_cap_s() == 3600.0


# --- #2: a run in flight reports "running", not the initial "pending_stream" ---


def test_run_reports_running_while_executing(client, _lift_runs_ratelimit, monkeypatch):
    async def _slow(agent, conv, *, event_sink=None, **kw):
        await asyncio.sleep(0.8)  # a window where the run is mid-flight
        return types.SimpleNamespace(final_output="listo")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _slow)

    run_id = _post_rich(client)
    # Poll status (each GET also pumps the app loop so the background task runs).
    # We must observe "running" — the state the route now sets while executing,
    # distinct from the initial "pending_stream" — before it reaches "completed".
    seen: list[str] = []
    deadline = time.time() + 5
    while time.time() < deadline:
        st = _status(client, run_id)
        seen.append(st)
        if st == "completed":
            break
        time.sleep(0.03)

    assert "running" in seen, f"never observed 'running'; saw {sorted(set(seen))}"
    assert seen[-1] == "completed"


# --- #3: the wall-cap fires on a stuck/slow run, freeing the model slot ---


def test_wall_cap_stops_a_stuck_run(client, _lift_runs_ratelimit, monkeypatch):
    monkeypatch.setenv("KRYON_RUN_MAX_WALL_S", "0.3")

    async def _stuck(agent, conv, *, event_sink=None, **kw):
        await asyncio.sleep(30)  # would hold the (single-slot) model forever
        return types.SimpleNamespace(final_output="never")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _stuck)

    run_id = _post_rich(client)
    # The 0.3s cap fires long before the 30s sleep → the run ends "incomplete"
    # (a graceful partial stop), not wedged; the background task is cancelled.
    assert _wait_status(client, run_id, {"incomplete"}, timeout=5) == "incomplete"


def test_wall_cap_disabled_lets_run_complete(client, _lift_runs_ratelimit, monkeypatch):
    monkeypatch.setenv("KRYON_RUN_MAX_WALL_S", "0")  # disabled

    async def _quick(agent, conv, *, event_sink=None, **kw):
        await asyncio.sleep(0.1)
        return types.SimpleNamespace(final_output="ok")

    monkeypatch.setattr("kryon.cli.reflective_runner.run_with_reflection", _quick)

    run_id = _post_rich(client)
    # With the cap off, a normal run reaches "completed" (no spurious timeout).
    assert _wait_status(client, run_id, {"completed"}, timeout=5) == "completed"
