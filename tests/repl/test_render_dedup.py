"""F77.D / Fase 11 — render dedup contract.

`items_to_messages()` in the SDK adapter walks the full item history every
turn to rebuild the API payload, which re-fires the render hooks for every
previously-seen tool call. Without dedup, a tool from turn 1 prints
(1 + remaining_turns) times — the bug visible in the operator screenshot.

These tests pin down the dedup helper that guards both render sites
(Fase 8 invocation glyph in the SDK adapter, Fase 6 completion glyph in
streaming.cli_print_tool_output).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset() -> None:
    """Each test starts with a clean dedup ledger."""
    from kryon.util.streaming import _reset_render_dedup

    _reset_render_dedup()
    yield
    _reset_render_dedup()


def test_first_call_returns_false_and_marks() -> None:
    from kryon.util.streaming import _dedup_render_check

    assert _dedup_render_check("invocation", "call_abc") is False


def test_second_call_returns_true() -> None:
    from kryon.util.streaming import _dedup_render_check

    _dedup_render_check("invocation", "call_abc")
    assert _dedup_render_check("invocation", "call_abc") is True


def test_distinct_call_ids_do_not_collide() -> None:
    from kryon.util.streaming import _dedup_render_check

    _dedup_render_check("invocation", "call_abc")
    assert _dedup_render_check("invocation", "call_xyz") is False


def test_invocation_and_completion_are_independent_stages() -> None:
    """A call_id seen as 'invocation' must still emit on 'completion'.
    Otherwise the `▸` would hide the `✓ summary` for the same tool."""
    from kryon.util.streaming import _dedup_render_check

    assert _dedup_render_check("invocation", "call_abc") is False
    # completion stage is a different bucket.
    assert _dedup_render_check("completion", "call_abc") is False
    # second hit on each stage now dedupes.
    assert _dedup_render_check("invocation", "call_abc") is True
    assert _dedup_render_check("completion", "call_abc") is True


def test_empty_call_id_never_dedupes() -> None:
    """When call_id is missing/empty we can't tell duplicates apart, so we
    err on the side of showing it — better than swallowing real output."""
    from kryon.util.streaming import _dedup_render_check

    assert _dedup_render_check("invocation", "") is False
    assert _dedup_render_check("invocation", "") is False  # still false
    assert _dedup_render_check("invocation", None) is False


def test_reset_clears_state() -> None:
    from kryon.util.streaming import _dedup_render_check, _reset_render_dedup

    _dedup_render_check("invocation", "call_abc")
    assert _dedup_render_check("invocation", "call_abc") is True

    _reset_render_dedup()
    # After reset the same call_id is "fresh" again — simulates a new turn.
    assert _dedup_render_check("invocation", "call_abc") is False


def test_reset_safe_when_never_initialized() -> None:
    """Calling reset before the first check shouldn't crash."""
    from kryon.util.streaming import _dedup_render_check, _reset_render_dedup

    # If the autouse fixture already ran, _seen exists. Re-test by deleting.
    if hasattr(_dedup_render_check, "_seen"):
        del _dedup_render_check._seen

    # Reset on a virgin module state must be a no-op, not an AttributeError.
    _reset_render_dedup()
    # And subsequent normal use still works.
    assert _dedup_render_check("invocation", "call_x") is False


def test_simulates_multi_turn_history_replay() -> None:
    """The exact scenario from the screenshot bug: turn 1 ran call_a +
    call_b. Turn 2 ran call_c. items_to_messages re-walks history each
    turn. Without dedup, call_a + call_b would each print twice on turn 2."""
    from kryon.util.streaming import _dedup_render_check

    # Turn 1 — first encounter of call_a, call_b → both render.
    assert _dedup_render_check("invocation", "call_a") is False
    assert _dedup_render_check("completion", "call_a") is False
    assert _dedup_render_check("invocation", "call_b") is False
    assert _dedup_render_check("completion", "call_b") is False

    # Turn 2 begins. items_to_messages re-walks the entire history.
    # call_a and call_b should be recognized as "already rendered".
    assert _dedup_render_check("invocation", "call_a") is True
    assert _dedup_render_check("completion", "call_a") is True
    assert _dedup_render_check("invocation", "call_b") is True
    assert _dedup_render_check("completion", "call_b") is True

    # The new turn-2 tool call is fresh and renders.
    assert _dedup_render_check("invocation", "call_c") is False
    assert _dedup_render_check("completion", "call_c") is False
