"""Concurrency helpers shared across the CLI / REPL / tool layers."""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable
from typing import Any


def run_with_timeout(fn: Callable, *args: Any, wall_timeout: float, **kwargs: Any) -> Any:
    """Run ``fn(*args, **kwargs)`` with a hard wall timeout that NEVER blocks on a
    hung worker.

    A plain ``with ThreadPoolExecutor() as ex: fut.result(timeout=T)`` calls
    ``shutdown(wait=True)`` on ``__exit__``, which JOINS the worker — so a stuck
    subprocess (e.g. a nuclei scan, an unresponsive MCP RPC, a wedged ``kryon
    engage`` child) blocks the whole caller despite the ``result(timeout=...)``.
    Here we ``shutdown(wait=False, cancel_futures=True)`` and let the orphan
    finish/die on its own, so the caller always makes progress.

    Raises ``concurrent.futures.TimeoutError`` on overrun (the caller handles it).
    ``wall_timeout`` is this helper's budget; any ``timeout=`` in kwargs is
    forwarded to ``fn`` (callers whose target takes its own timeout).
    """
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn, *args, **kwargs)
    try:
        return fut.result(timeout=wall_timeout)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
