"""T4-A3: a reverse-shell/bind listener must be auto-backgrounded (async session)
even when interactive=True is not set. Run serially it blocks run_command until
timeout and the payload that connects back never fires (foothold lost)."""

from __future__ import annotations

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import kryon.tools.reconnaissance.run_command as rc
from kryon.sdk.agents import RunContextWrapper


def _route(monkeypatch, command: str, interactive: bool = False) -> str:
    """Return 'session' if routed to the backgrounded session path, 'blocking'
    if routed to the synchronous path."""
    calls = {"which": None}

    def fake_sync(*a, **kw):
        calls["which"] = "session"
        return "Started async session S1"

    async def fake_async(*a, **kw):
        calls["which"] = "blocking"
        return "done"

    monkeypatch.setattr(rc, "_run_cmd", fake_sync)
    monkeypatch.setattr(rc, "_run_cmd_async", fake_async)

    import asyncio

    payload = {"command": command, "interactive": interactive}
    asyncio.run(rc.run_command.on_invoke_tool(RunContextWrapper(None), json.dumps(payload)))
    return calls["which"]


def test_nc_listener_autobackgrounds_without_flag(monkeypatch):
    assert _route(monkeypatch, "nc -lvnp 4444") == "session"


def test_socat_listener_autobackgrounds(monkeypatch):
    assert _route(monkeypatch, "socat TCP-LISTEN:9001,reuseaddr,fork -") == "session"


def test_rlwrap_wrapped_listener_autobackgrounds(monkeypatch):
    # wrapper must be unwrapped to see the real nc binary
    assert _route(monkeypatch, "rlwrap nc -lvnp 4444") == "session"


def test_plain_curl_stays_blocking(monkeypatch):
    assert _route(monkeypatch, "curl http://127.0.0.1/") == "blocking"


def test_nc_connect_is_not_a_listener(monkeypatch):
    # outbound nc (no -l) is a normal blocking command
    assert _route(monkeypatch, "nc 10.0.0.5 4444") == "blocking"
