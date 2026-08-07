"""Per-chunk timeout: a hung chunk must be aborted so the loop always ends."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import Mock, patch

from kryon.cli.reflective_runner import run_with_reflection


async def test_hung_chunk_is_aborted_and_loop_terminates(monkeypatch):
    """A chunk that never returns must not hang the runner — the per-chunk
    timeout aborts it and the loop bails out after a couple of timeouts.

    Regression for the 100%-CPU hang where a stuck agent step kept the
    investigate alive forever (the wall budget only checks between chunks).
    """
    monkeypatch.setenv("KRYON_CHUNK_TIMEOUT_S", "1")

    async def _hang(*args, **kwargs):
        await asyncio.sleep(30)  # a chunk that never returns

    import kryon.sdk.agents.run as runmod

    start = time.monotonic()
    with patch.object(runmod.Runner, "run", new=_hang):
        await run_with_reflection(
            agent=Mock(),
            initial_input="go",
            reflect_every=2,
            max_total_turns=4,
        )
    elapsed = time.monotonic() - start
    # Without the timeout this hangs ~30s+; with it, two 1s chunk timeouts bail.
    assert elapsed < 10
