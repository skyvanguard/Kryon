"""FASE 6 — runtime bridge between reflective_runner and the
``execute_planner_directive`` function_tool.

The planner runs *inside* ``run_with_reflection``: that's where
``accumulated_facts`` and ``tool_history`` live. But the
``execute_planner_directive`` tool gets called from the LLM's tool-use
loop, which has no reference to those structures. This module bridges
that gap with a ``contextvars.ContextVar`` set by the reflective
runner around each chunk and read by the tool.

Why ContextVar and not a module-level global: the SDK's async loop
may interleave coroutines across runs in the same process (notably
the agent runtime + a future parallel orchestrator). A global would
mix state across runs; ``ContextVar`` is per-task by design.

Banca-safe: this module owns no I/O, no network, no LLM calls. It
holds a single immutable snapshot in the context var and exposes
read-only accessors.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

from kryon.intelligence.fact_extractor import EMPTY, ExtractedFacts


@dataclass(frozen=True)
class PlannerRuntimeState:
    """Snapshot of what ``execute_planner_directive`` needs to call
    the planner. Set by ``run_with_reflection`` after each chunk."""

    facts: ExtractedFacts
    prior_tool_args: tuple[str, ...]  # flat list of args_preview strings


_DEFAULT_STATE = PlannerRuntimeState(facts=EMPTY, prior_tool_args=())

# Per-task variable. ``None`` means "no run is currently being driven
# by the reflective runner" — the tool then refuses to execute (the
# planner needs facts + history to make sense, and without them it
# would emit the empty-state recommendation every time).
_current_state: ContextVar["PlannerRuntimeState | None"] = ContextVar(
    "kryon_planner_runtime_state", default=None,
)


def set_current_state(
    facts: ExtractedFacts,
    prior_tool_args: tuple[str, ...] | list[str],
) -> None:
    """Update the per-task runtime snapshot. Called by
    ``run_with_reflection`` once per chunk, after extracting facts +
    refreshing the tool history."""
    if not isinstance(prior_tool_args, tuple):
        prior_tool_args = tuple(prior_tool_args)
    _current_state.set(PlannerRuntimeState(facts=facts, prior_tool_args=prior_tool_args))


def clear_current_state() -> None:
    """Reset the per-task snapshot. Called by ``run_with_reflection``
    on exit so a leaked ContextVar doesn't feed stale state into a
    later run in the same task."""
    _current_state.set(None)


def get_current_state() -> "PlannerRuntimeState | None":
    """Read the per-task runtime snapshot. Returns ``None`` when no
    reflective run is in flight."""
    return _current_state.get()


def get_current_state_or_default() -> PlannerRuntimeState:
    """Like ``get_current_state`` but returns the empty default
    instead of ``None`` — for tests / callers that prefer a
    non-optional shape."""
    state = _current_state.get()
    return state if state is not None else _DEFAULT_STATE


__all__ = [
    "PlannerRuntimeState",
    "set_current_state",
    "clear_current_state",
    "get_current_state",
    "get_current_state_or_default",
]
