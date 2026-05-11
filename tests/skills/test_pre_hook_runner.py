"""Tests for the pre-hook execution runner.

Covers:
  - Sync + async tool callables
  - Template substitution from ctx
  - Required vs optional failure semantics
  - Timeout enforcement
  - Tool not in registry → error
  - Multiple hooks execute in order, outputs merged correctly
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from kryon.skills.pre_hook_runner import (
    PreHookExecutionError,
    run_pre_hooks,
)
from kryon.skills.pre_hook_spec import parse_pre_hooks

# ---------- Helpers ----------


def _make_hook(**overrides: Any) -> tuple:
    """Build a parsed PreHookSpec tuple from a single dict."""
    base = {"tool": "fake_tool"}
    base.update(overrides)
    return parse_pre_hooks([base])


# ---------- Happy path ----------


@pytest.mark.asyncio
async def test_runs_single_sync_tool_and_returns_dict() -> None:
    hooks = _make_hook(tool="fake_tool", inject_as="result")
    callables = {"fake_tool": lambda: "deterministic output"}

    out = await run_pre_hooks(hooks, ctx={}, tool_callables=callables)

    assert out == {"result": "deterministic output"}


@pytest.mark.asyncio
async def test_runs_single_async_tool() -> None:
    async def async_tool() -> str:
        await asyncio.sleep(0.01)
        return "async output"

    hooks = _make_hook(tool="async_tool")
    callables = {"async_tool": async_tool}

    out = await run_pre_hooks(hooks, ctx={}, tool_callables=callables)

    assert out["async_tool"] == "async output"


@pytest.mark.asyncio
async def test_template_substitution_from_ctx() -> None:
    received_kwargs: dict[str, Any] = {}

    def capture_args(**kwargs: Any) -> str:
        received_kwargs.update(kwargs)
        return "ok"

    hooks = parse_pre_hooks([
        {
            "tool": "compliance",
            "args": {
                "framework": "fortigate",
                "host": "{ctx.host}",
                "ssh_user": "{ctx.ssh_user}",
            },
        }
    ])
    ctx = {"host": "192.168.1.1", "ssh_user": "auditor"}

    await run_pre_hooks(hooks, ctx=ctx, tool_callables={"compliance": capture_args})

    assert received_kwargs == {
        "framework": "fortigate",
        "host": "192.168.1.1",
        "ssh_user": "auditor",
    }


@pytest.mark.asyncio
async def test_template_with_missing_ctx_var_substitutes_empty() -> None:
    """If ctx is missing a whitelisted var, sub becomes empty string —
    not a crash. This is intentional: skills should be resilient when
    optional context (e.g. ssh_user) isn't provided."""
    received: dict[str, Any] = {}

    def capture(**kwargs: Any) -> str:
        received.update(kwargs)
        return "ok"

    hooks = parse_pre_hooks([
        {"tool": "x", "args": {"host": "{ctx.host}", "user": "{ctx.ssh_user}"}}
    ])
    ctx = {"host": "10.0.0.1"}  # no ssh_user

    await run_pre_hooks(hooks, ctx=ctx, tool_callables={"x": capture})
    assert received["host"] == "10.0.0.1"
    assert received["user"] == ""


@pytest.mark.asyncio
async def test_multiple_hooks_run_in_order_and_merge() -> None:
    call_order: list[str] = []

    def first() -> str:
        call_order.append("first")
        return "A"

    def second() -> str:
        call_order.append("second")
        return "B"

    hooks = parse_pre_hooks([
        {"tool": "first", "inject_as": "alpha"},
        {"tool": "second", "inject_as": "beta"},
    ])

    out = await run_pre_hooks(
        hooks, ctx={}, tool_callables={"first": first, "second": second}
    )

    assert call_order == ["first", "second"]
    assert out == {"alpha": "A", "beta": "B"}


@pytest.mark.asyncio
async def test_tool_returning_json_is_passed_through() -> None:
    payload = {"verdicts": {"PASS": 5, "FAIL": 3}, "hash": "abc"}

    def compliance() -> str:
        return json.dumps(payload)

    hooks = _make_hook(tool="compliance")
    out = await run_pre_hooks(hooks, ctx={}, tool_callables={"compliance": compliance})

    assert json.loads(out["compliance"]) == payload


# ---------- Failure paths ----------


@pytest.mark.asyncio
async def test_unknown_tool_required_raises() -> None:
    hooks = _make_hook(tool="ghost_tool", required=True)
    with pytest.raises(PreHookExecutionError, match="not in callable registry"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


@pytest.mark.asyncio
async def test_unknown_tool_optional_continues() -> None:
    """required=False → log + placeholder, no exception."""
    hooks = _make_hook(tool="ghost_tool", required=False, inject_as="ghost")
    out = await run_pre_hooks(hooks, ctx={}, tool_callables={})

    assert "ghost" in out
    assert "failed" in out["ghost"]


@pytest.mark.asyncio
async def test_tool_raising_required_propagates() -> None:
    def boom() -> str:
        raise ValueError("downstream broke")

    hooks = _make_hook(tool="boom", required=True)

    with pytest.raises(PreHookExecutionError, match="downstream broke"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={"boom": boom})


@pytest.mark.asyncio
async def test_tool_raising_optional_continues_with_placeholder() -> None:
    def boom() -> str:
        raise ValueError("oops")

    def succeed() -> str:
        return "fine"

    hooks = parse_pre_hooks([
        {"tool": "boom", "required": False, "inject_as": "broke"},
        {"tool": "succeed", "inject_as": "ok"},
    ])

    out = await run_pre_hooks(
        hooks, ctx={}, tool_callables={"boom": boom, "succeed": succeed}
    )

    assert "failed" in out["broke"]
    assert out["ok"] == "fine"


@pytest.mark.asyncio
async def test_timeout_required_raises() -> None:
    async def slow() -> str:
        await asyncio.sleep(2)
        return "never"

    hooks = _make_hook(tool="slow", timeout_s=1, required=True)

    with pytest.raises(PreHookExecutionError, match="timed out"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={"slow": slow})


@pytest.mark.asyncio
async def test_timeout_optional_continues() -> None:
    async def slow() -> str:
        await asyncio.sleep(2)
        return "never"

    hooks = _make_hook(
        tool="slow", timeout_s=1, required=False, inject_as="timed_out"
    )
    out = await run_pre_hooks(hooks, ctx={}, tool_callables={"slow": slow})

    assert "timed out" in out["timed_out"]


# ---------- Python escape hatch (Fase 5) ----------

_FIXTURE_DIR = str(__import__("pathlib").Path(__file__).parent / "fixtures")


@pytest.mark.asyncio
async def test_python_hatch_sync_callable_runs() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:run_sync"}],
        source_dir=_FIXTURE_DIR,
    )
    out = await run_pre_hooks(
        hooks, ctx={"host": "192.168.1.1"}, tool_callables={}
    )
    assert "sync hook saw host='192.168.1.1'" in out["run_sync"]


@pytest.mark.asyncio
async def test_python_hatch_async_callable_runs() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:run_async"}],
        source_dir=_FIXTURE_DIR,
    )
    out = await run_pre_hooks(
        hooks, ctx={"ssh_user": "auditor"}, tool_callables={}
    )
    assert "async hook ssh_user='auditor'" in out["run_async"]


@pytest.mark.asyncio
async def test_python_hatch_returns_dict_serializes_to_json() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:returns_dict", "inject_as": "result"}],
        source_dir=_FIXTURE_DIR,
    )
    out = await run_pre_hooks(
        hooks, ctx={"host": "10.0.0.1"}, tool_callables={}
    )
    parsed = json.loads(out["result"])
    assert parsed["verdicts"]["PASS"] == 5
    assert parsed["host"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_python_hatch_failing_required_raises() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:fails"}], source_dir=_FIXTURE_DIR
    )
    with pytest.raises(PreHookExecutionError, match="expected failure for tests"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


@pytest.mark.asyncio
async def test_python_hatch_failing_optional_continues() -> None:
    hooks = parse_pre_hooks(
        [{
            "python": "./sample_hook.py:fails",
            "required": False,
            "inject_as": "broke",
        }],
        source_dir=_FIXTURE_DIR,
    )
    out = await run_pre_hooks(hooks, ctx={}, tool_callables={})
    assert "failed" in out["broke"]


@pytest.mark.asyncio
async def test_python_hatch_timeout_enforced() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:slow", "timeout_s": 1}],
        source_dir=_FIXTURE_DIR,
    )
    with pytest.raises(PreHookExecutionError, match="timed out"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


@pytest.mark.asyncio
async def test_python_hatch_function_not_found_raises() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:does_not_exist"}],
        source_dir=_FIXTURE_DIR,
    )
    with pytest.raises(PreHookExecutionError, match="not found or not callable"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


@pytest.mark.asyncio
async def test_python_hatch_attribute_is_not_callable_raises() -> None:
    """Module exports a name but it's not a function (e.g. a constant)."""
    hooks = parse_pre_hooks(
        [{"python": "./sample_hook.py:not_a_function"}],
        source_dir=_FIXTURE_DIR,
    )
    with pytest.raises(PreHookExecutionError, match="not callable"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


@pytest.mark.asyncio
async def test_python_hatch_missing_file_raises() -> None:
    hooks = parse_pre_hooks(
        [{"python": "./does_not_exist.py:run"}],
        source_dir=_FIXTURE_DIR,
    )
    with pytest.raises(PreHookExecutionError, match="not found"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


@pytest.mark.asyncio
async def test_python_hatch_no_source_dir_raises() -> None:
    """Specs built without source_dir (typical of direct test usage when
    the author forgets to pass it) get a clear error."""
    hooks = parse_pre_hooks([{"python": "./sample_hook.py:run_sync"}])
    # No source_dir → resolution should fail loudly.
    with pytest.raises(PreHookExecutionError, match="no source_dir"):
        await run_pre_hooks(hooks, ctx={}, tool_callables={})


# ---------- Edge ----------


@pytest.mark.asyncio
async def test_empty_hooks_returns_empty_dict() -> None:
    assert await run_pre_hooks((), ctx={}, tool_callables={}) == {}


@pytest.mark.asyncio
async def test_non_string_return_is_coerced_to_string() -> None:
    """dicts and lists get JSON-encoded; everything else uses str()."""
    def returns_dict() -> str:  # type: ignore[return-value]
        return {"a": 1}  # type: ignore[return-value]

    hooks = _make_hook(tool="t")
    out = await run_pre_hooks(hooks, ctx={}, tool_callables={"t": returns_dict})

    assert isinstance(out["t"], str)
    # JSON encoding produces double-quoted keys.
    assert json.loads(out["t"]) == {"a": 1}


@pytest.mark.asyncio
async def test_non_string_non_dict_uses_str_repr() -> None:
    def returns_int() -> str:  # type: ignore[return-value]
        return 42  # type: ignore[return-value]

    hooks = _make_hook(tool="t")
    out = await run_pre_hooks(hooks, ctx={}, tool_callables={"t": returns_int})

    assert out["t"] == "42"
