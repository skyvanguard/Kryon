"""Integration tests — pre_hook_integration glues spec/runner to the agent.

These are unit tests with synthetic agents (no real Runner.run / model calls).
They validate the bits the REPL relies on:
  - Tool extraction from agent.tools (uses `_raw_fn`)
  - Turn ctx construction from env + user input
  - Findings block formatting
  - End-to-end maybe_run_pre_hooks() with mock agent
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import pytest

from kryon.skills.pre_hook_integration import (
    build_tool_callables_from_agent,
    build_turn_ctx,
    collect_active_pre_hooks,
    format_findings_block,
    maybe_run_pre_hooks,
)
from kryon.skills.pre_hook_spec import parse_pre_hooks

# ---------- Stubs ----------


class _FakeTool:
    """Minimal shape of a function_tool: has .name and ._raw_fn."""

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self._raw_fn = fn


class _FakeSkill:
    def __init__(self, name: str, pre_hooks: tuple = ()) -> None:
        self.name = name
        self.pre_hooks = pre_hooks


class _FakeAgent:
    def __init__(self, tools: list[Any], skills: list[Any]) -> None:
        self.tools = tools
        self._active_skills = skills


# ---------- build_tool_callables_from_agent ----------


def test_extracts_callables_via_raw_fn() -> None:
    def fn_a() -> str:
        return "a"

    def fn_b() -> str:
        return "b"

    agent = _FakeAgent(
        tools=[_FakeTool("alpha", fn_a), _FakeTool("beta", fn_b)],
        skills=[],
    )
    callables = build_tool_callables_from_agent(agent)
    assert set(callables.keys()) == {"alpha", "beta"}
    assert callables["alpha"]() == "a"


def test_skips_tools_without_raw_fn() -> None:
    """MCP-bridged tools have no _raw_fn — must be skipped silently."""

    class _MCPLike:
        name = "mcp_tool"
        # no _raw_fn

    agent = _FakeAgent(tools=[_MCPLike()], skills=[])
    assert build_tool_callables_from_agent(agent) == {}


def test_handles_agent_without_tools_attr() -> None:
    class _Bare:
        pass

    assert build_tool_callables_from_agent(_Bare()) == {}


# ---------- build_turn_ctx ----------


def test_ctx_from_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_TARGET_HOST", "fw.empresa.local")
    monkeypatch.setenv("KRYON_SSH_USER", "auditor")
    monkeypatch.setenv("KRYON_SSH_KEY", "/keys/id_ed25519")
    monkeypatch.setenv("KRYON_SSH_PORT", "2222")
    monkeypatch.setenv("KRYON_CLIENT_NAME", "BritImp")

    ctx = build_turn_ctx(user_input="auditá esto")
    assert ctx["host"] == "fw.empresa.local"
    assert ctx["ssh_user"] == "auditor"
    assert ctx["ssh_key_path"] == "/keys/id_ed25519"
    assert ctx["ssh_port"] == "2222"
    assert ctx["client_name"] == "BritImp"


def test_ctx_detects_ipv4_in_user_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRYON_TARGET_HOST", raising=False)
    ctx = build_turn_ctx(user_input="auditá el fortigate 192.168.1.1 ya")
    assert ctx["host"] == "192.168.1.1"
    assert ctx["target"] == "192.168.1.1"


def test_ctx_detects_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRYON_TARGET_HOST", raising=False)
    ctx = build_turn_ctx(user_input="scan unifi.empresa.com please")
    assert ctx["host"] == "unifi.empresa.com"


def test_ctx_env_takes_precedence_over_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_TARGET_HOST", "10.0.0.1")
    ctx = build_turn_ctx(user_input="probar 192.168.1.1")
    assert ctx["host"] == "10.0.0.1"


def test_ctx_empty_when_nothing_to_detect(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in (
        "KRYON_TARGET_HOST",
        "KRYON_SSH_USER",
        "KRYON_SSH_KEY",
        "KRYON_SSH_PORT",
        "KRYON_CLIENT_NAME",
        "KRYON_SESSION_ID",
    ):
        monkeypatch.delenv(k, raising=False)
    ctx = build_turn_ctx(user_input="hola")
    assert ctx["host"] == ""
    assert ctx["ssh_user"] == ""


# ---------- collect_active_pre_hooks ----------


def test_collect_flattens_hooks_from_active_skills() -> None:
    h1 = parse_pre_hooks([{"tool": "a"}])
    h2 = parse_pre_hooks([{"tool": "b"}, {"tool": "c"}])
    agent = _FakeAgent(
        tools=[],
        skills=[_FakeSkill("s1", h1), _FakeSkill("s2", h2)],
    )
    flat = collect_active_pre_hooks(agent)
    assert [h.tool for h in flat] == ["a", "b", "c"]


def test_collect_returns_empty_when_no_skills() -> None:
    assert collect_active_pre_hooks(_FakeAgent(tools=[], skills=[])) == []


# ---------- format_findings_block ----------


def test_format_empty_findings_returns_empty_string() -> None:
    assert format_findings_block({}) == ""


def test_format_pretty_prints_json_payload() -> None:
    findings = {"compliance": json.dumps({"verdicts": {"PASS": 5, "FAIL": 3}})}
    block = format_findings_block(findings)
    assert "## Pre-hook deterministic context" in block
    assert "### compliance" in block
    assert '"PASS": 5' in block  # pretty-printed JSON
    assert "do NOT re-run" in block  # authoritative warning to LLM


def test_format_falls_back_for_non_json() -> None:
    findings = {"raw": "not json at all"}
    block = format_findings_block(findings)
    assert "not json at all" in block


# ---------- maybe_run_pre_hooks (end-to-end) ----------


@pytest.mark.asyncio
async def test_maybe_run_returns_empty_when_no_hooks() -> None:
    agent = _FakeAgent(tools=[], skills=[_FakeSkill("noop", ())])
    out = await maybe_run_pre_hooks(agent, user_input="hi", console=None)
    assert out == ""


@pytest.mark.asyncio
async def test_maybe_run_invokes_hook_and_returns_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRYON_TARGET_HOST", "192.168.1.1")
    monkeypatch.setenv("KRYON_SSH_USER", "auditor")

    captured_kwargs: dict[str, Any] = {}

    def compliance_audit(**kwargs: Any) -> str:
        captured_kwargs.update(kwargs)
        return json.dumps({"verdicts": {"PASS": 3, "FAIL": 18}, "hash": "abc"})

    hooks = parse_pre_hooks(
        [
            {
                "tool": "run_compliance_audit",
                "args": {"framework": "fortigate", "host": "{ctx.host}", "ssh_user": "{ctx.ssh_user}"},
                "inject_as": "compliance",
            }
        ]
    )
    agent = _FakeAgent(
        tools=[_FakeTool("run_compliance_audit", compliance_audit)],
        skills=[_FakeSkill("fortigate-audit", hooks)],
    )

    out = await maybe_run_pre_hooks(agent, user_input="auditá esto", console=None)

    # Tool received substituted args
    assert captured_kwargs == {
        "framework": "fortigate",
        "host": "192.168.1.1",
        "ssh_user": "auditor",
    }
    # Output is a markdown block with the findings
    assert "### compliance" in out
    assert '"PASS": 3' in out
    assert '"FAIL": 18' in out


@pytest.mark.asyncio
async def test_maybe_run_required_failure_returns_error_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a required hook can't find its tool, return a clear error
    block instead of crashing the turn — the LLM will tell the user."""

    hooks = parse_pre_hooks(
        [
            {
                "tool": "missing_tool",  # not in callable registry
                "required": True,
                "inject_as": "x",
            }
        ]
    )
    agent = _FakeAgent(tools=[], skills=[_FakeSkill("s", hooks)])

    out = await maybe_run_pre_hooks(agent, user_input="x", console=None)
    assert "_pre_hook_error" in out
    assert "Required pre-hook failed" in out


@pytest.mark.asyncio
async def test_maybe_run_with_console_does_not_crash() -> None:
    """Smoke: console.print path with a real Rich Console."""
    from rich.console import Console

    def t() -> str:
        return json.dumps({"ok": True})

    hooks = parse_pre_hooks([{"tool": "t", "inject_as": "result"}])
    agent = _FakeAgent(tools=[_FakeTool("t", t)], skills=[_FakeSkill("s", hooks)])

    # If console.print throws, the call is wrapped in try/except → no crash.
    out = await maybe_run_pre_hooks(agent, user_input="x", console=Console())
    assert "### result" in out
