"""Tests for run endpoints."""


def test_get_run_not_found(client):
    resp = client.get("/api/v1/runs/nonexistent")
    assert resp.status_code == 404


def test_cancel_run_not_found(client):
    resp = client.delete("/api/v1/runs/nonexistent")
    assert resp.status_code == 404


def test_create_run_unknown_agent_resolves_to_unified(client, monkeypatch):
    """PR #57 (unified-only): ``get_agent_by_name`` returns the unified Kryon
    agent for ANY key, so the old 404-on-unknown-agent path is dead — the run
    proceeds normally. (Was ``test_create_run_invalid_agent`` asserting 404,
    stale since the legacy per-name agents were removed.)"""
    from types import SimpleNamespace

    from kryon.sdk.agents import Runner

    async def _ok(*args, **kwargs):
        return SimpleNamespace(
            final_output="done",
            last_agent=SimpleNamespace(name="Kryon"),
            raw_responses=[],
            to_input_list=lambda: [],
        )

    monkeypatch.setattr(Runner, "run", _ok)

    resp = client.post(
        "/api/v1/runs",
        json={"agent_key": "nonexistent_agent_xyz", "input": "hello"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


def test_create_run_stuck_returns_partial_not_500(client, monkeypatch):
    """P0 symmetry: a stuck-loop (StuckError) is a graceful partial stop →
    HTTP 200 with status='stuck', NOT an opaque 500 (the CyberGym bench gap)."""
    from kryon.sdk.agents import Runner
    from kryon.sdk.agents.exceptions import StuckError

    async def _raise_stuck(*args, **kwargs):
        raise StuckError(tool_name="run_command", repeat_count=4, window_size=6)

    monkeypatch.setattr(Runner, "run", _raise_stuck)

    resp = client.post("/api/v1/runs", json={"agent_key": "kryon", "input": "loop"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "stuck"
    assert "run_command" in body["output"]


def test_create_run_genuine_crash_still_500(client, monkeypatch):
    """A non-recoverable exception must still surface as an opaque 500."""
    from kryon.sdk.agents import Runner

    async def _boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(Runner, "run", _boom)

    resp = client.post("/api/v1/runs", json={"agent_key": "kryon", "input": "crash"})

    assert resp.status_code == 500
