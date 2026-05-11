"""TDD contract for kryon.repl.ui.tool_output_buffer.

Per-turn buffer that holds tool outputs collapsed by render_tool_completion
so the operator can recover them via `/show <N>`. The full output also
goes to the JSONL audit log — buffer is just for interactive recall.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_buffer():
    from kryon.repl.ui.tool_output_buffer import reset

    reset()
    yield
    reset()


# ---------- Basic store / retrieve ----------


def test_empty_buffer_returns_none() -> None:
    from kryon.repl.ui.tool_output_buffer import get

    assert get(1) is None


def test_record_and_retrieve_returns_what_was_stored() -> None:
    from kryon.repl.ui.tool_output_buffer import get, record

    step = record(tool_name="run_command", output="hello world")
    assert isinstance(step, int)
    assert step >= 1
    entry = get(step)
    assert entry is not None
    assert entry["tool_name"] == "run_command"
    assert entry["output"] == "hello world"


def test_record_increments_step_id() -> None:
    from kryon.repl.ui.tool_output_buffer import record

    s1 = record(tool_name="a", output="x")
    s2 = record(tool_name="b", output="y")
    s3 = record(tool_name="c", output="z")
    assert s1 < s2 < s3


def test_get_unknown_step_returns_none() -> None:
    from kryon.repl.ui.tool_output_buffer import get, record

    record(tool_name="a", output="x")
    assert get(999) is None


# ---------- Turn boundary ----------


def test_new_turn_resets_step_counter() -> None:
    from kryon.repl.ui.tool_output_buffer import new_turn, record

    s1 = record(tool_name="a", output="x")
    new_turn()
    s2 = record(tool_name="b", output="y")
    # After new_turn, counter restarts at 1.
    assert s2 == 1
    # And the previous step is gone.
    from kryon.repl.ui.tool_output_buffer import get

    assert get(s1) is None or get(s1)["tool_name"] == "b"  # either gone or replaced


def test_new_turn_clears_old_entries() -> None:
    from kryon.repl.ui.tool_output_buffer import (
        get,
        new_turn,
        record,
    )

    record(tool_name="x", output="y")
    record(tool_name="x", output="y")
    new_turn()
    # All previous step ids are now invalid.
    assert get(1) is None
    assert get(2) is None


# ---------- Size cap (no memory leak) ----------


def test_record_caps_individual_output_size() -> None:
    """Long outputs (e.g. nmap full XML) get truncated in the buffer to
    keep memory bounded. The ORIGINAL output still goes to the JSONL log;
    this is just the interactive cache."""
    from kryon.repl.ui.tool_output_buffer import (
        MAX_OUTPUT_BYTES_PER_STEP,
        get,
        record,
    )

    huge = "x" * (MAX_OUTPUT_BYTES_PER_STEP * 3)
    step = record(tool_name="t", output=huge)
    entry = get(step)
    assert entry is not None
    # Output capped — exact behavior is "truncated with marker".
    assert len(entry["output"]) <= MAX_OUTPUT_BYTES_PER_STEP + 200  # allow for marker


def test_buffer_caps_max_steps_per_turn() -> None:
    """Per-turn step count caps to avoid unbounded growth on a chatty
    agent. After the cap, oldest entries are evicted (FIFO)."""
    from kryon.repl.ui.tool_output_buffer import (
        MAX_STEPS_PER_TURN,
        get,
        record,
    )

    # Record beyond the cap.
    ids = [record(tool_name=f"t{i}", output=f"o{i}") for i in range(MAX_STEPS_PER_TURN + 5)]
    # Most recent steps must still be retrievable.
    last = ids[-1]
    assert get(last) is not None
    # Earliest steps may have been evicted. We don't require it; just
    # that the buffer didn't grow unbounded — total live entries
    # should stay near MAX_STEPS_PER_TURN.
    from kryon.repl.ui.tool_output_buffer import live_count

    assert live_count() <= MAX_STEPS_PER_TURN


# ---------- Thread safety ----------


def test_concurrent_record_and_get_does_not_crash() -> None:
    """Toolbar / agent loop / /show command run in different threads."""
    import threading

    from kryon.repl.ui.tool_output_buffer import get, record

    stop = threading.Event()

    def writer():
        while not stop.is_set():
            record(tool_name="t", output="x")

    def reader():
        while not stop.is_set():
            get(1)
            get(50)

    t1 = threading.Thread(target=writer, daemon=True)
    t2 = threading.Thread(target=reader, daemon=True)
    t1.start()
    t2.start()
    import time

    time.sleep(0.05)
    stop.set()
    t1.join(timeout=1)
    t2.join(timeout=1)


# ---------- Edge cases ----------


def test_record_with_empty_output_still_returns_id() -> None:
    """Empty / None output is valid — caller may want to record metadata
    even when there was no body."""
    from kryon.repl.ui.tool_output_buffer import get, record

    s = record(tool_name="t", output="")
    entry = get(s)
    assert entry is not None
    assert entry["output"] == ""


def test_record_with_none_output_normalizes_to_empty_string() -> None:
    from kryon.repl.ui.tool_output_buffer import get, record

    s = record(tool_name="t", output=None)
    entry = get(s)
    assert entry is not None
    assert entry["output"] == ""
