"""F85.E — StuckDetector unit tests.

Verifies the triple-hash sliding-window pattern recommended by prior
art (Manus / agent-patterns / AutoGPT post-mortem):

  - Identical (tool, args, result) repeated → intervention then abort
  - Identical tool but DIFFERENT args → polling, never blocks
  - Identical tool+args but DIFFERENT results → still progressing
  - Window slides: old entries fall off after N
  - Args canonicalised so {"a":1,"b":2} == {"b":2,"a":1}
"""

from __future__ import annotations

import pytest

from kryon.sdk.agents._stuck_detector import StuckAction, StuckDetector


def test_first_call_always_continues():
    det = StuckDetector()
    action = det.record("nmap", {"target": "x"}, "open: 22")
    assert action.kind == "continue"


def test_two_identical_triples_emit_intervention():
    det = StuckDetector(window_size=5, intervene_at=2, abort_at=3)
    det.record("get_users", "{}", "alice,bob")
    action = det.record("get_users", "{}", "alice,bob")
    assert action.kind == "intervene"
    assert action.tool_name == "get_users"
    assert action.repeat_count == 2
    assert "reconsider" in action.message.lower()


def test_three_identical_triples_emit_abort():
    det = StuckDetector(window_size=5, intervene_at=2, abort_at=3)
    det.record("get_users", "{}", "alice,bob")
    det.record("get_users", "{}", "alice,bob")  # intervene
    action = det.record("get_users", "{}", "alice,bob")
    assert action.kind == "abort"
    assert action.repeat_count == 3


def test_intervention_emitted_only_once_per_triple():
    """The same triple shouldn't yield two intervene actions before
    abort — the second time we hit intervene_at threshold for an
    already-intervened triple, we keep counting toward abort."""
    det = StuckDetector(window_size=5, intervene_at=2, abort_at=4)
    det.record("x", "{}", "y")
    a1 = det.record("x", "{}", "y")
    assert a1.kind == "intervene"
    a2 = det.record("x", "{}", "y")
    assert a2.kind == "continue", "second intervention for same triple suppressed"


def test_different_args_dont_count_as_repeat():
    """Polling with varying args is legitimate behaviour, not a loop."""
    det = StuckDetector()
    for tgt in ["host-a", "host-b", "host-c", "host-d", "host-e"]:
        action = det.record("ping", {"target": tgt}, "alive")
        assert action.kind == "continue", f"args={tgt} got {action.kind}"


def test_different_results_dont_count_as_repeat():
    """Same tool+args but progressively different results means the
    agent IS making progress (e.g., paginated reads)."""
    det = StuckDetector()
    for i in range(5):
        action = det.record("read_page", '{"page": 1}', f"chunk-{i}")
        assert action.kind == "continue"


def test_window_slides_so_old_loops_age_out():
    """If the same triple appears 2 times then 3 OTHER calls happen,
    a single subsequent re-occurrence is not "the third strike"
    because the first 2 fell out of the window."""
    det = StuckDetector(window_size=3, intervene_at=2, abort_at=3)
    det.record("a", "{}", "x")
    det.record("a", "{}", "x")  # intervene
    det.record("b", "{}", "y")
    det.record("c", "{}", "z")
    det.record("d", "{}", "w")
    # First two ('a', ...) are now out of the 3-slot window.
    action = det.record("a", "{}", "x")
    assert action.kind == "continue"


def test_arg_order_does_not_matter():
    """{'a':1,'b':2} and {'b':2,'a':1} must hash to the same args key."""
    det = StuckDetector()
    det.record("t", {"a": 1, "b": 2}, "r")
    action = det.record("t", {"b": 2, "a": 1}, "r")
    assert action.kind == "intervene", "args canonicalised to same hash"


def test_string_args_and_dict_args_with_same_payload_collide():
    """SDK passes args as JSON string; tests sometimes use dicts.
    Both should hash to the same key when the content is equivalent."""
    det = StuckDetector()
    det.record("t", '{"k": 1}', "r")
    action = det.record("t", {"k": 1}, "r")
    assert action.kind == "intervene"


def test_abort_at_must_exceed_intervene_at():
    with pytest.raises(ValueError, match="abort_at"):
        StuckDetector(intervene_at=3, abort_at=3)


def test_intervene_at_must_be_at_least_two():
    """intervene_at=1 makes no sense — the very first call has no
    repeat yet."""
    with pytest.raises(ValueError, match="intervene_at"):
        StuckDetector(intervene_at=1, abort_at=2)


def test_reset_clears_state():
    det = StuckDetector(intervene_at=2, abort_at=3)
    det.record("a", "{}", "x")
    det.record("a", "{}", "x")
    det.reset()
    # After reset, the next 'a' is fresh; needs 2 more to trigger intervene
    action = det.record("a", "{}", "x")
    assert action.kind == "continue"


def test_unhashable_args_fall_back_to_repr():
    """Tool args can theoretically contain non-JSON types (set, etc).
    The detector should not crash — fall back to repr-based hashing."""
    det = StuckDetector()
    weird_args = {"set": {1, 2, 3}}  # sets are not JSON-serializable
    # Should not raise
    a1 = det.record("t", weird_args, "r")
    a2 = det.record("t", weird_args, "r")
    assert a1.kind == "continue"
    assert a2.kind == "intervene"
