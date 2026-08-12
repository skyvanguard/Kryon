"""Ring-buffer replay correctness for the SSE stream reader.

``RunState.events`` is a bounded deque; a run that emits more frames than the buffer
holds drops its oldest ones. The stream reader must map its consumed-cursor onto the
live window (``events_since``) instead of indexing positionally — the old
``run.events[idx]`` mis-served the instant eviction shifted the deque, and its ``idx``
could run past a ``len`` capped at ``maxlen`` and hang the tail forever. These lock
the eviction-aware behavior in.
"""

from __future__ import annotations

from collections import deque

from kryon.server.sessions import RunState


def _mk(maxlen: int | None = None) -> RunState:
    rs = RunState(run_id="r", session_id=None, agent_key="kryon")
    if maxlen is not None:
        rs.events = deque(maxlen=maxlen)  # shrink the ring to exercise eviction
    return rs


def test_append_event_buffers_and_counts():
    rs = _mk()
    for i in range(3):
        rs.append_event(f"f{i}")
    assert len(rs.events) == 3
    assert rs.total_events == 3
    assert [e["sse"] for e in rs.events] == ["f0", "f1", "f2"]


def test_events_since_empty():
    assert _mk().events_since(0) == ([], 0)


def test_events_since_serves_all_then_nothing():
    rs = _mk()
    for i in range(3):
        rs.append_event(f"f{i}")
    out, served = rs.events_since(0)
    assert out == ["f0", "f1", "f2"]
    assert served == 3
    # A caller that already consumed everything gets nothing and the same cursor.
    assert rs.events_since(served) == ([], 3)


def test_events_since_incremental_delivery():
    rs = _mk()
    for i in range(3):
        rs.append_event(f"f{i}")
    _out, served = rs.events_since(0)
    assert served == 3
    rs.append_event("f3")
    rs.append_event("f4")
    out2, served2 = rs.events_since(served)
    assert out2 == ["f3", "f4"]  # only the new frames, not a re-send
    assert served2 == 5


def test_overflow_fresh_reader_gets_live_window_not_evicted():
    # Buffer holds 5; 8 appended → frames 0,1,2 evicted.
    rs = _mk(maxlen=5)
    for i in range(8):
        rs.append_event(f"f{i}")
    assert len(rs.events) == 5
    assert rs.total_events == 8
    out, served = rs.events_since(0)
    assert out == ["f3", "f4", "f5", "f6", "f7"]  # the live window, in order
    assert served == 8  # cursor jumps to total → the reader won't loop on evicted frames


def test_overflow_reader_within_window_no_loss():
    rs = _mk(maxlen=5)
    for i in range(8):
        rs.append_event(f"f{i}")
    # Reader had consumed 5 (absolute) and is still inside the live window [3,8).
    out, served = rs.events_since(5)
    assert out == ["f5", "f6", "f7"]
    assert served == 8


def test_overflow_reader_far_behind_degrades_gracefully():
    rs = _mk(maxlen=5)
    for i in range(8):
        rs.append_event(f"f{i}")
    # Reader only consumed 1 but frames 1,2 were evicted — it resumes from the oldest
    # live frame (f3), losing the evicted ones, without crashing or duplicating.
    out, served = rs.events_since(1)
    assert out == ["f3", "f4", "f5", "f6", "f7"]
    assert served == 8


def test_reader_loop_terminates_and_serves_tail_on_overflow():
    # Mirror the _event_generator poll loop: keep calling events_since(served). It must
    # converge (return []) after draining — proving no infinite spin on an overflowed
    # buffer, the failure the old positional idx caused.
    rs = _mk(maxlen=5)
    for i in range(12):
        rs.append_event(f"f{i}")
    served = 0
    collected: list[str] = []
    for _ in range(100):  # bounded — must settle well before this
        new, served = rs.events_since(served)
        collected.extend(new)
        if not new:
            break
    assert collected == ["f7", "f8", "f9", "f10", "f11"]  # last 5 live frames
    assert served == 12
    # A subsequent poll yields nothing (the real loop would sleep, not spin).
    assert rs.events_since(served) == ([], 12)
