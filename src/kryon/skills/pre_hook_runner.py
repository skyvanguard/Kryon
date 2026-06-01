"""Pre-hook execution runner.

Runs declarative pre_hooks BEFORE the LLM takes control of a turn:
  1. Template-substitute args from the turn context (whitelist only).
  2. Invoke the tool callable (sync or async) with a per-hook timeout.
  3. Collect outputs into a dict keyed by `inject_as`.
  4. Honour `required: true|false` for failure semantics.

The caller (run loop) is responsible for:
  - Building `tool_callables` mapping (tool name → plain Python callable).
    Callables receive the substituted args as **kwargs and must return
    a string (typically JSON). We accept sync and async callables.
  - Inserting the returned `{inject_as: output}` dict into the system
    prompt or as a synthetic tool message before the model runs.

Security model:
  - Templates are pre-validated by `parse_pre_hooks` (only `{ctx.X}`
    placeholders from ALLOWED_TEMPLATE_VARS pass).
  - We do not eval; substitution is exact-match string replace.
  - `required: true` failure aborts the turn — surfaces an explicit
    error to the user instead of silently letting the LLM run without
    the deterministic context.
"""

from __future__ import annotations

import asyncio
import glob
import importlib.util
import inspect
import logging
import os
import re
import signal
from pathlib import Path
from typing import Any, Awaitable, Callable, Union

from kryon.skills.pre_hook_spec import (
    ALLOWED_TEMPLATE_VARS,
    PreHookSpec,
)

logger = logging.getLogger(__name__)


# Same regex used at parse time. Re-using ensures parity: anything that
# slipped past parse-time validation also fails (or runs) here identically.
_TEMPLATE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\}")


ToolCallable = Callable[..., Union[str, Awaitable[str]]]


class PreHookExecutionError(RuntimeError):
    """Raised when a `required: true` pre-hook fails or times out.

    The caller should surface this to the user as `[pre-hook X failed: ...]`
    and abort the turn rather than let the LLM continue without the
    deterministic context.
    """


def _substitute_one(value: Any, ctx: dict[str, Any]) -> Any:
    """Substitute `{ctx.X}` placeholders in a single value.

    Non-string values pass through unchanged. Unknown vars (after parse-
    time validation) become an empty string with a warning — defensive,
    should not happen if the spec was parsed via `parse_pre_hooks`.
    """
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in ALLOWED_TEMPLATE_VARS:
            logger.warning("pre_hook template var %r escaped parse-time check", var)
            return ""
        # ctx is flat: ctx.host → ctx["host"], ctx.ssh_user → ctx["ssh_user"]
        key = var.split(".", 1)[1] if "." in var else var
        sub_value = ctx.get(key, "")
        return str(sub_value) if sub_value is not None else ""

    return _TEMPLATE_RE.sub(replace, value)


def _substitute_args(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    """Apply `_substitute_one` to every value in the args dict."""
    return {k: _substitute_one(v, ctx) for k, v in args.items()}


def _resolve_python_callable(hook: PreHookSpec) -> Callable[..., Any]:
    """Load `<source_dir>/<file>` and return its `<func>` attribute.

    Sandbox rules (path-based — Fase 5 baseline):
      - `source_dir` MUST be set by the loader. Specs built directly
        without a source_dir cause a clear error.
      - The resolved file path MUST be inside the Kryon repo root.
        `.resolve()` follows symlinks, so escape-via-symlink is caught.
      - The file MUST exist as a regular file.

    The hook's `python` field has the form `./<rel>.py:<func>` —
    enforced by the schema parser at frontmatter parse time.
    """
    if not hook.source_dir:
        raise PreHookExecutionError(
            f"python hook {hook.python!r} has no source_dir — either declare "
            "it in a skill .md (loader injects source_dir) or pass source_dir "
            "to parse_pre_hooks() in tests"
        )

    file_part, _, func_name = hook.python.rpartition(":")
    rel = file_part[2:] if file_part.startswith("./") else file_part

    file_path = (Path(hook.source_dir) / rel).resolve()

    # Sandbox: refuse anything that resolves outside the Kryon repo root.
    # __file__ → .../src/kryon/skills/pre_hook_runner.py → parents[3] = repo.
    repo_root = Path(__file__).resolve().parents[3]
    try:
        file_path.relative_to(repo_root)
    except ValueError as e:
        raise PreHookExecutionError(
            f"python hook path {file_path} resolves outside the Kryon repo ({repo_root}) — refused"
        ) from e

    if not file_path.is_file():
        raise PreHookExecutionError(f"python hook file not found: {file_path}")

    mod_name = f"_kryon_pre_hook_{file_path.stem}_{abs(hash(str(file_path)))}"
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    if spec is None or spec.loader is None:
        raise PreHookExecutionError(f"could not build import spec for {file_path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise PreHookExecutionError(f"failed to import {file_path}: {type(e).__name__}: {e}") from e

    func = getattr(module, func_name, None)
    if not callable(func):
        raise PreHookExecutionError(f"function {func_name!r} not found or not callable in {file_path}")
    return func


def _all_descendants(pid: int) -> set[int]:
    """Recursive child PIDs of ``pid`` via /proc (Linux); empty elsewhere.

    ``asyncio.wait_for`` cancels the await on timeout but cannot kill the
    executor thread running a sync hook — so its subprocess (nuclei/sqlmap/...)
    survives at 100% CPU. We snapshot children before the hook and kill any new
    ones on timeout.
    """
    out: set[int] = set()
    stack = [pid]
    while stack:
        cur = stack.pop()
        try:
            for ch_file in glob.glob(f"/proc/{cur}/task/*/children"):
                with open(ch_file, encoding="ascii") as f:
                    for tok in f.read().split():
                        cpid = int(tok)
                        if cpid not in out:
                            out.add(cpid)
                            stack.append(cpid)
        except (OSError, ValueError):
            continue
    return out


# SIGKILL is Unix-only (the pre_hook runner runs in the Linux container);
# fall back to SIGTERM on Windows so unit tests on the host don't break.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


def _kill_pids(pids: set[int]) -> None:
    """Hard-kill each pid, best-effort (already-gone / denied is fine)."""
    for p in pids:
        try:
            os.kill(p, _SIGKILL)
        except (ProcessLookupError, PermissionError, OSError, ValueError):
            pass


async def _invoke_one(
    hook: PreHookSpec,
    ctx: dict[str, Any],
    tool_callables: dict[str, ToolCallable],
) -> str:
    """Run one hook (tool or python escape hatch) with timeout, return string."""
    label = hook.tool or hook.python or "(unknown)"

    if hook.python:
        # Python escape hatch: signature is `func(ctx: dict) -> str | dict`.
        # We pass the full context so the hook author can run conditional
        # logic. `args:` from the spec is ignored for python hooks (they
        # have Python in hand — they don't need a YAML DSL).
        callable_ = _resolve_python_callable(hook)
        if inspect.iscoroutinefunction(callable_):
            coro = callable_(ctx)
        else:
            loop = asyncio.get_running_loop()
            coro = loop.run_in_executor(None, lambda: callable_(ctx))
    else:
        callable_ = tool_callables.get(hook.tool)
        if callable_ is None:
            raise PreHookExecutionError(
                f"pre_hook tool {hook.tool!r} not in callable registry (available: {sorted(tool_callables.keys())})"
            )
        args = _substitute_args(hook.args, ctx)
        if inspect.iscoroutinefunction(callable_):
            coro = callable_(**args)
        else:
            loop = asyncio.get_running_loop()
            coro = loop.run_in_executor(None, lambda: callable_(**args))

    _self_pid = os.getpid()
    _children_before = _all_descendants(_self_pid)
    try:
        result = await asyncio.wait_for(coro, timeout=hook.timeout_s)
    except asyncio.TimeoutError as e:
        # wait_for cancelled the await, but a sync hook's executor thread (and
        # its subprocess, e.g. nuclei/sqlmap) keeps running. Kill the orphaned
        # children so they don't peg the CPU indefinitely after the timeout.
        _orphans = _all_descendants(_self_pid) - _children_before
        _kill_pids(_orphans)
        raise PreHookExecutionError(
            f"pre_hook {label!r} timed out after {hook.timeout_s}s "
            f"(killed {len(_orphans)} orphaned subprocess(es))"
        ) from e
    except PreHookExecutionError:
        raise
    except Exception as e:  # noqa: BLE001
        raise PreHookExecutionError(f"pre_hook {label!r} raised: {type(e).__name__}: {e}") from e

    if not isinstance(result, str):
        # Coerce for downstream consumers. Pretty-encode dicts/lists.
        if isinstance(result, (dict, list)):
            import json

            try:
                result = json.dumps(result, ensure_ascii=False)
            except (TypeError, ValueError):
                result = str(result)
        else:
            result = str(result)
    return result


async def run_pre_hooks(
    hooks: tuple[PreHookSpec, ...],
    ctx: dict[str, Any],
    tool_callables: dict[str, ToolCallable],
) -> dict[str, str]:
    """Execute every hook in order, return `{inject_as: output_str}`.

    On a `required: true` failure: raises PreHookExecutionError immediately.
    On a `required: false` failure: logs a warning, injects an explanatory
    placeholder string under the inject_as key, continues to next hook.

    Args:
        hooks: tuple from `Skill.pre_hooks` (already schema-validated).
        ctx: flat dict of context vars. Keys: host, ssh_user, ssh_key_path,
            ssh_port, target, session_id, client_name (any subset OK).
        tool_callables: mapping tool_name → plain python callable.

    Returns:
        Dict {inject_as: str output}. May contain `[pre_hook X failed: ...]`
        placeholder strings for non-required failures.
    """
    if not hooks:
        return {}

    out: dict[str, str] = {}
    for hook in hooks:
        try:
            result = await _invoke_one(hook, ctx, tool_callables)
            out[hook.inject_as] = result
            logger.debug(
                "pre_hook ok: %s → %d chars under %r",
                hook.tool or hook.python,
                len(result),
                hook.inject_as,
            )
        except PreHookExecutionError as e:
            if hook.required:
                raise
            logger.warning("pre_hook (required=false) failed: %s", e)
            out[hook.inject_as] = f"[pre_hook {hook.tool!r} failed: {e}]"

    return out
