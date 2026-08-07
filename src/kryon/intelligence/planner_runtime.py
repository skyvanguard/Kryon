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

import logging
import os
from contextvars import ContextVar
from dataclasses import dataclass

from kryon.intelligence.fact_extractor import EMPTY, ExtractedFacts

logger = logging.getLogger(__name__)

_DEFAULT_DIRECTIVE_CONFIDENCE_THRESHOLD = 0.92


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
    "kryon_planner_runtime_state",
    default=None,
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


# The user's objective ("active pentest … WordPress /blog vhost internal.thm"). plan_next_action takes an
# ``intent`` that several rules gate on (the wpscan rule fires on "wordpress"/"/blog" in intent OR facts),
# but ``execute_planner_directive`` was passing ``intent=""`` because the runtime snapshot never carried it
# — so WP/keyword-gated rules only fired when the markers happened to land in facts.paths, which they DON'T
# from a web_fetch JSON envelope (body_md/links, not the wp-content/wp-includes asset hrefs). Result on THM
# Internal: the planner skipped wpscan entirely and wandered into jwt_forge/ssrf. Set once per run.
_planner_intent: ContextVar[str] = ContextVar("kryon_planner_intent", default="")


def set_planner_intent(intent: str) -> None:
    """Record the run's objective so ``execute_planner_directive`` can pass it to the planner. Called once
    by ``run_with_reflection`` before ``Runner.run`` so the tool's child task inherits the value."""
    _planner_intent.set((intent or "")[:2000])


def get_planner_intent() -> str:
    """Read the run's objective. ``""`` when none was set (tests / non-reflective callers)."""
    return _planner_intent.get()


def peek_planner_subcalls() -> list[str]:
    """Read the per-task sub-call log WITHOUT clearing it.

    ``state.prior_tool_args`` is a snapshot the reflective runner refreshes once per CHUNK, but the LLM
    calls ``execute_planner_directive`` MULTIPLE times within a single chunk. Sub-calls only fold into
    ``prior_tool_args`` at the next chunk boundary (via ``drain`` → ``set_current_state``), so without a
    peek the 2nd, 3rd… directive of the same chunk re-plan against the stale snapshot — the rule that
    just fired still passes its ``_was_invoked`` gate and the planner returns the IDENTICAL rec, looping
    until the StuckDetector intervenes (observed live on THM Internal). The executor folds this peek into
    the ``prior_tool_args`` it passes to ``plan_next_action`` so each directive sees the earlier sub-calls
    of the same chunk and advances the chain. Read-only: ``drain`` (chunk boundary) still owns clearing.
    """
    buf = _subcall_log.get()
    return list(buf) if buf else []


# Intra-chunk fact accumulator. ``state.facts`` only refreshes at the chunk boundary, but a directive that
# cracks a credential (wpscan → admin:my2boys) needs the rule that consumes it (wp_webshell, gated on
# facts.creds) to fire in the SAME chunk — otherwise the planner has nothing productive left and wanders
# into spurious rules (jwt_forge) until the budget dies. Each directive extracts facts from its OWN sub-call
# output and appends them here; the next directive of the chunk merges them over the snapshot. Same in-place
# list pattern as the sub-call log (child-task safe — appends on the shared ref, never ``.set`` from a child).
_chunk_facts_log: ContextVar[list[ExtractedFacts] | None] = ContextVar(
    "kryon_planner_chunk_facts",
    default=None,
)


def record_chunk_facts(facts: ExtractedFacts) -> None:
    """Append facts extracted from a directive's sub-call output so the NEXT directive of the same chunk
    sees them. No-op for EMPTY. In-place append on the shared list (parent primes it via
    ``init_chunk_facts`` before ``Runner.run``); a child task ``.set`` would not propagate back."""
    if facts is None or facts is EMPTY:
        return
    buf = _chunk_facts_log.get()
    if buf is None:
        _chunk_facts_log.set([facts])
        return
    buf.append(facts)


def get_chunk_facts() -> ExtractedFacts:
    """Merge all facts this chunk's directives have accumulated so far. ``EMPTY`` when none."""
    buf = _chunk_facts_log.get()
    if not buf:
        return EMPTY
    merged = buf[0]
    for extra in buf[1:]:
        merged = merged.merge(extra)
    return merged


def init_chunk_facts() -> None:
    """Prime the per-chunk fact accumulator to an empty list (parent, before ``Runner.run``) so the
    executor's child task shares the ref. Called once per chunk alongside ``init_planner_subcall_log``."""
    _chunk_facts_log.set([])


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


# FASE 11.Q — high-confidence directive detection for SDK-level
# ``tool_choice="required"`` forcing. Resolves the sampling-variance
# bottleneck where qwen3-8b-active emits the directive's narrated tool
# call only ~30% of runs even when the OPERATOR DIRECTIVE block is in
# the reflection turn. Forcing ``tool_choice="required"`` for that
# specific model call closes the gap.
#
# Banca-safe: read-only inspection of the per-task state. Returns False
# when no reflective run is in flight, when no rule fires, or when the
# confidence is below threshold. Wrapped in a try/except so a planner
# rule bug never bubbles up into the SDK call path.


def has_high_confidence_directive(threshold: float | None = None) -> bool:
    """Return True when the planner would emit a directive with
    confidence ≥ ``threshold`` against the current per-task state.

    Used by the SDK to decide whether to force ``tool_choice="required"``
    for the next model call so the model can't sample-its-way out of
    invoking ``execute_planner_directive``.

    Args:
        threshold: minimum confidence to count as "high". Defaults to
            ``KRYON_PLANNER_DIRECTIVE_THRESHOLD`` env (parsed as float),
            falling back to 0.92 — the same cutoff
            ``render_for_prompt`` uses to escalate the prompt block.

    Returns False when:
      - no reflective run is in flight (state is None);
      - the planner returns None (no rule fires);
      - the rec's confidence is below threshold;
      - any exception bubbles up from rule evaluation (logged at debug).
    """
    if threshold is None:
        env_value = os.environ.get("KRYON_PLANNER_DIRECTIVE_THRESHOLD")
        if env_value:
            try:
                threshold = float(env_value)
            except ValueError:
                threshold = _DEFAULT_DIRECTIVE_CONFIDENCE_THRESHOLD
        else:
            threshold = _DEFAULT_DIRECTIVE_CONFIDENCE_THRESHOLD

    state = _current_state.get()
    if state is None:
        return False

    # Import inside the function to avoid a circular import at module
    # load (planner_runtime is imported by the SDK, and the SDK is
    # imported by the planner module's distillation loader path).
    try:
        from kryon.intelligence.exploit_chain_planner import plan_next_action
    except Exception as exc:  # noqa: BLE001
        logger.debug("exploit_chain_planner unavailable: %s", exc)
        return False

    try:
        rec = plan_next_action(state.facts, list(state.prior_tool_args))
    except Exception as exc:  # noqa: BLE001 — never propagate to SDK
        logger.debug("plan_next_action raised in directive probe: %s", exc)
        return False

    if rec is None:
        return False
    return rec.confidence >= threshold


__all__ = [
    "PlannerRuntimeState",
    "set_current_state",
    "clear_current_state",
    "get_current_state",
    "get_current_state_or_default",
    "record_planner_subcall",
    "drain_planner_subcalls",
    "peek_planner_subcalls",
    "init_planner_subcall_log",
    "record_chunk_facts",
    "get_chunk_facts",
    "init_chunk_facts",
    "set_planner_intent",
    "get_planner_intent",
    "has_high_confidence_directive",
]
