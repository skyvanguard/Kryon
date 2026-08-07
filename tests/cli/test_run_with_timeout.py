"""_run_with_timeout: a hard wall timeout that never blocks on a hung worker.

Regression for the webexploit phase hanging on a nuclei subprocess: a plain
``with ThreadPoolExecutor() as ex: fut.result(timeout=T)`` joins the worker on
``__exit__`` (shutdown wait=True), so a stuck worker blocked the whole investigate
despite the ``result(timeout=...)``.
"""

from __future__ import annotations

import concurrent.futures
import time

import pytest

from kryon.cli.investigate import _run_with_timeout


def test_returns_value_when_fn_completes():
    assert _run_with_timeout(lambda x: x + 1, 41, wall_timeout=5) == 42


def test_forwards_kwargs_including_a_timeout_kwarg():
    # A ``timeout=`` kwarg must reach fn (web_enum takes its own), NOT be
    # swallowed by the helper's own wall budget.
    def fn(a, *, timeout):
        return (a, timeout)

    assert _run_with_timeout(fn, "x", timeout=99, wall_timeout=5) == ("x", 99)


def test_raises_timeout_without_blocking_on_hung_worker():
    started = time.monotonic()

    def _hang():
        time.sleep(30)  # a worker that ignores the budget (nuclei subprocess)

    with pytest.raises(concurrent.futures.TimeoutError):
        _run_with_timeout(_hang, wall_timeout=0.5)
    # The point: we return ~immediately at the timeout, NOT after the worker's 30s.
    assert time.monotonic() - started < 5


def test_propagates_fn_exception():
    def _boom():
        raise ValueError("nope")

    with pytest.raises(ValueError, match="nope"):
        _run_with_timeout(_boom, wall_timeout=5)
