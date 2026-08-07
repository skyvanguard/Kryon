"""T4-M2: write-back must not block investigate exit when the embedding store hangs
(air-gapped / no ONNX model). add_experience runs under a wall-clock timeout."""

from __future__ import annotations

import os
import time

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.services import investigate_writeback as wb


class _Result:
    final_output = "shell obtained, root flag captured"
    new_items: list = []


def _chain(_result):
    return [{"tool": "nmap", "args": {}}, {"tool": "sqlmap", "args": {}}]


def test_hung_embedding_is_skipped_by_timeout(monkeypatch):
    monkeypatch.setenv("KRYON_WRITEBACK_TIMEOUT_S", "0.3")
    monkeypatch.setattr(wb, "chain_from_result", _chain)

    import kryon.learning.experiences as exp

    def _hang(_experience):
        time.sleep(5)  # simulate the 60s ONNX/ChromaDB hang
        return "should-never-return"

    monkeypatch.setattr(exp, "add_experience", _hang)

    t0 = time.time()
    out = wb.write_back_from_investigate("audit box", {"mode": "general"}, _Result(), auto_synth=False)
    elapsed = time.time() - t0

    assert out is None  # skipped, not the hung id
    assert elapsed < 3.0  # returned on the ~0.3s timeout, did not wait 5s


def test_fast_embedding_returns_id(monkeypatch):
    monkeypatch.setenv("KRYON_WRITEBACK_TIMEOUT_S", "5")
    monkeypatch.setattr(wb, "chain_from_result", _chain)

    import kryon.learning.experiences as exp

    monkeypatch.setattr(exp, "add_experience", lambda _e: "exp-123")
    out = wb.write_back_from_investigate("audit box", {"mode": "general"}, _Result(), auto_synth=False)
    assert out == "exp-123"
