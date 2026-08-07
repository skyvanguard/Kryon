"""Regression tests for the HIGH pre-hook fixes:
- ctx-value sanitization lives in the RUNNER (not only the glue layer), so it
  holds regardless of which caller assembled the ctx (command-injection guard).
- a required-hook failure no longer discards the remaining hooks in the turn.
"""

from __future__ import annotations

import pytest

from kryon.skills.pre_hook_runner import (
    PreHookExecutionError,
    _substitute_args,
    run_pre_hooks,
)
from kryon.skills.pre_hook_spec import parse_pre_hooks


def test_runner_sanitizes_shell_metachars_in_ctx_value() -> None:
    # A ctx value with shell metacharacters blanks out at substitution time,
    # even though this ctx never passed through build_turn_ctx's _safe_ctx.
    out = _substitute_args({"cmd": "ping {ctx.host}"}, {"host": "evil.com; rm -rf /"})
    assert ";" not in out["cmd"]
    assert "rm" not in out["cmd"]
    assert out["cmd"] == "ping "  # whole unsafe value → empty


def test_runner_passes_clean_ctx_value_through() -> None:
    out = _substitute_args({"cmd": "ping {ctx.host}"}, {"host": "example.com"})
    assert out["cmd"] == "ping example.com"


async def test_required_failure_still_runs_later_hooks(tmp_path) -> None:
    hooks = parse_pre_hooks(
        [
            {"tool": "boom", "required": True, "inject_as": "a"},
            {"tool": "later", "required": False, "inject_as": "b"},
        ],
        source_dir=str(tmp_path),
    )
    calls: list[int] = []

    def later() -> str:
        calls.append(1)
        return "later-ran"

    # "boom" is absent from the callable registry → its invocation raises;
    # being required, it must NOT abort "later".
    with pytest.raises(PreHookExecutionError, match="required pre_hook"):
        await run_pre_hooks(hooks, {}, {"later": later})

    assert calls == [1], "the later hook must still run despite the required failure"
