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
_current_state: ContextVar[PlannerRuntimeState | None] = ContextVar(
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


def get_current_state() -> PlannerRuntimeState | None:
    """Read the per-task runtime snapshot. Returns ``None`` when no
    reflective run is in flight."""
    return _current_state.get()


def get_current_state_or_default() -> PlannerRuntimeState:
    """Like ``get_current_state`` but returns the empty default
    instead of ``None`` — for tests / callers that prefer a
    non-optional shape."""
    state = _current_state.get()
    return state if state is not None else _DEFAULT_STATE


# FASE 11.M — sub-call append/drain log.
#
# When ``execute_planner_directive`` runs a tool internally (gobuster,
# nuclei, sqlmap, ...), the reflective runner's ``tool_history`` only
# sees the ``execute_planner_directive`` wrapper invocation — not the
# args of the underlying command. That breaks ``_was_invoked``
# substring checks in planner rules (cascade gobuster, port pivot,
# etc.) since they look for strings like ``common.txt`` or
# ``gobuster`` that only ever appear in the inner args.
#
# The executor appends each inner args string here; the runner drains
# the log at each reflection boundary and merges them into the
# ``tool_history`` it passes to the planner. Same ContextVar pattern
# as the state snapshot above (per-task isolation, no globals).
_subcall_log: ContextVar[list[str] | None] = ContextVar(
    "kryon_planner_subcall_log",
    default=None,
)


def record_planner_subcall(args: str) -> None:
    """Append a sub-call args string to the per-task log.

    Called by ``execute_planner_directive`` after the underlying
    ``run_command_async`` returns. Empty/whitespace strings are
    silently ignored — a ``_was_invoked(prior_args, "")`` check
    would match anything, so we never want an empty entry in the
    log.

    Critical invariant: this function MUST NOT call
    ``_subcall_log.set()`` because the executor often runs in a
    child asyncio task whose ContextVar writes don't propagate back
    to the parent (the reflective runner). The runner is expected
    to have called ``init_planner_subcall_log`` before its
    ``Runner.run`` invocation, so ``buf`` here is the SAME list
    object the runner will drain. Appends mutate that list in-place
    and are visible to the parent.

    If ``buf`` is somehow ``None`` (e.g. tool invoked outside a
    reflective run for tests), we still create an isolated list and
    accept that those entries won't be drained — better than
    crashing.
    """
    if not args or not args.strip():
        return
    buf = _subcall_log.get()
    if buf is None:
        # Standalone path (no reflective runner around us). Set the
        # ContextVar so subsequent appends in the SAME context still
        # accumulate, even if the parent never reads them.
        buf = [args]
        _subcall_log.set(buf)
        return
    buf.append(args)


def drain_planner_subcalls() -> list[str]:
    """Read + clear the per-task sub-call log.

    Called by ``run_with_reflection`` at the start of each chunk's
    post-processing so the entries land in the next reflection's
    ``tool_history`` (and therefore the next planner pass's
    ``prior_tool_args``).

    Returns an empty list when the log was never touched in this
    task. Always clears the buffer (in-place mutation, NOT
    ``ContextVar.set``) so two consecutive drains return
    ``[entries], []``. In-place mutation is required because
    ``ContextVar.set`` from inside a child task (e.g. the executor)
    doesn't propagate back to the parent — see
    ``init_planner_subcall_log`` for the matching initialization
    invariant.
    """
    buf = _subcall_log.get()
    if buf is None:
        return []
    drained = list(buf)
    # Mutate the existing list in-place rather than replacing the ref
    # via ContextVar.set — the executor's child-task view holds the
    # same ref, and a .set() here would only swap the parent's view.
    buf.clear()
    return drained


def init_planner_subcall_log() -> None:
    """Initialize the per-task sub-call log to an empty list.

    Called by ``run_with_reflection`` BEFORE each ``Runner.run`` call
    so the executor (which may live in a child asyncio task) sees a
    fully-initialized list ref. The executor then only ever appends
    to that list (never calls ``.set``), so the parent's view stays
    in sync.

    Without this priming step, the executor's ``record_planner_
    subcall`` would call ``_subcall_log.set([new_list])`` on first
    invocation in a child task, and the parent never sees that
    list — appends land in the child's private view and disappear
    when the child task ends. This was the regression Bench Robots
    M (2026-05-26) exhibited.
    """
    _subcall_log.set([])


__all__ = [
    "PlannerRuntimeState",
    "set_current_state",
    "clear_current_state",
    "get_current_state",
    "get_current_state_or_default",
    "record_planner_subcall",
    "drain_planner_subcalls",
    "init_planner_subcall_log",
]
