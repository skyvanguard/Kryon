"""FASE 6 — planner_runtime ContextVar contract tests.

The runtime bridge is the seam between the reflective_runner (where
facts + tool history live) and the execute_planner_directive
function_tool (which the LLM invokes from inside the SDK tool-use
loop). The tests pin three invariants:

1. ``set_current_state`` snapshots the inputs (callers can mutate the
   passed list afterwards without leaking state into the ContextVar).
2. ``get_current_state`` returns ``None`` outside a set window —
   the tool must refuse rather than synthesizing a bogus run.
3. ``clear_current_state`` actually clears so the next run starts
   fresh.

ContextVar semantics aren't exercised here (single-task tests); the
parent-task isolation invariant is covered implicitly by the
SDK's own asyncio test suite.
"""

from __future__ import annotations

from kryon.intelligence.fact_extractor import EMPTY, ExtractedFacts
from kryon.intelligence.planner_runtime import (
    clear_current_state,
    get_current_state,
    get_current_state_or_default,
    set_current_state,
)


def test_state_defaults_to_none_outside_set_window() -> None:
    """Fresh ContextVar in this test's task scope → None."""
    clear_current_state()
    assert get_current_state() is None


def test_get_state_or_default_returns_empty_facts_when_unset() -> None:
    """For callers that want a non-Optional shape."""
    clear_current_state()
    state = get_current_state_or_default()
    assert state.facts is EMPTY
    assert state.prior_tool_args == ()


def test_set_state_then_get_returns_same_snapshot() -> None:
    facts = ExtractedFacts(users=("alice",), domains=("thm.local",))
    set_current_state(facts, ["nc 1.2.3.4 8000", "curl http://x"])
    state = get_current_state()
    assert state is not None
    assert state.facts is facts
    assert "nc 1.2.3.4 8000" in state.prior_tool_args
    clear_current_state()


def test_set_state_snapshots_prior_args_into_tuple() -> None:
    """Caller may pass a mutable list and then continue appending to
    it; the ContextVar must hold an immutable tuple of the values at
    set-time."""
    args_list = ["nc 1.2.3.4 8000"]
    set_current_state(EMPTY, args_list)
    args_list.append("LEAKED — should not be visible in snapshot")
    state = get_current_state()
    assert state is not None
    assert isinstance(state.prior_tool_args, tuple)
    assert "LEAKED — should not be visible in snapshot" not in state.prior_tool_args
    clear_current_state()


def test_clear_state_resets_to_none() -> None:
    set_current_state(EMPTY, ())
    assert get_current_state() is not None
    clear_current_state()
    assert get_current_state() is None


def test_state_facts_field_is_passthrough_not_copied() -> None:
    """ExtractedFacts is frozen, so identity preservation is fine and
    cheaper than a deep copy. Confirm the snapshot holds the same
    object."""
    facts = ExtractedFacts(users=("alice",))
    set_current_state(facts, ())
    state = get_current_state()
    assert state is not None
    assert state.facts is facts
    clear_current_state()


# ---------------------------------------------------------------------------
# FASE 11.M — sub-call exposure
# ---------------------------------------------------------------------------
#
# When ``execute_planner_directive`` runs a tool internally (e.g. fires a
# ``run_command gobuster ...`` after reading the planner's directive),
# the reflective runner's ``tool_history`` doesn't see the underlying
# command — only the wrapper invocation. That breaks rule abstain checks
# that key off the inner args (e.g. ``_was_invoked(prior_args, "common.txt")``).
#
# Fix: a small per-task append/drain log so the executor can record the
# args it ran and the runner can merge them into ``tool_history`` at
# the next reflection boundary.


def test_subcall_log_empty_by_default() -> None:
    """No record_planner_subcall calls → drain returns []."""
    from kryon.intelligence.planner_runtime import drain_planner_subcalls

    drain_planner_subcalls()  # clear any leftover from sibling tests
    assert drain_planner_subcalls() == []


def test_record_and_drain_returns_args_in_order() -> None:
    """Multiple recorded sub-calls drain in insertion order."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()  # clear
    record_planner_subcall("gobuster dir -u http://t/a -w common.txt")
    record_planner_subcall("gobuster dir -u http://t/b -w common.txt")
    drained = drain_planner_subcalls()
    assert len(drained) == 2
    assert "/a" in drained[0]
    assert "/b" in drained[1]


def test_drain_clears_the_buffer() -> None:
    """Second consecutive drain must be empty — the runner reads-
    and-clears each reflection boundary."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()
    record_planner_subcall("some-cmd --flag")
    assert drain_planner_subcalls() == ["some-cmd --flag"]
    assert drain_planner_subcalls() == []


def test_record_after_drain_starts_fresh_buffer() -> None:
    """Drain shouldn't leave the buffer in a state that rejects
    further appends — record after drain must accumulate normally."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()
    record_planner_subcall("first")
    drain_planner_subcalls()  # clear
    record_planner_subcall("second")
    assert drain_planner_subcalls() == ["second"]


def test_record_handles_empty_args_string() -> None:
    """Defensive — empty/whitespace args should not crash but also
    shouldn't pollute the log (downstream `_was_invoked` substring
    checks would silently match the empty string against anything)."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()
    record_planner_subcall("")
    record_planner_subcall("   ")
    assert drain_planner_subcalls() == []
