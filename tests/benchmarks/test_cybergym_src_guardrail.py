"""Guardrail: cybergym must NOT produce a phantom result when the agent can't
read the container-cloned source (host-agent vs container-source mismatch).

This exact mismatch made a host-run DeepSeek bench score 1/3 without ever
reading the code — it 'detected' from memory. The guardrail blocks it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.cybergym import runner


def _fake_docker_port(*_args, **_kwargs):
    # `docker port kryon` → the container publishes its API on host port 8700.
    return SimpleNamespace(stdout="8080/tcp -> 127.0.0.1:8700\n")


@pytest.mark.unit
def test_src_guardrail_blocks_host_agent_mismatch(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", _fake_docker_port)
    monkeypatch.delenv("KRYON_BENCH_SKIP_SRC_CHECK", raising=False)
    monkeypatch.setenv("KRYON_BENCH_CONTAINER", "kryon")

    # Agent reached on a host server (8702) ≠ the container's published port.
    monkeypatch.setenv("KRYON_API_URL", "http://127.0.0.1:8702")
    reason = runner._agent_can_see_source("/workspace/cybergym-src/heartbleed")
    assert reason and "phantom" in reason

    # Agent reached on the container's own published port → no mismatch.
    monkeypatch.setenv("KRYON_API_URL", "http://127.0.0.1:8700")
    assert runner._agent_can_see_source("/workspace/cybergym-src/heartbleed") == ""


@pytest.mark.unit
def test_src_guardrail_opt_out_and_non_container_paths(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", _fake_docker_port)
    monkeypatch.setenv("KRYON_API_URL", "http://127.0.0.1:8702")  # would mismatch

    # Explicit opt-out.
    monkeypatch.setenv("KRYON_BENCH_SKIP_SRC_CHECK", "1")
    assert runner._agent_can_see_source("/workspace/cybergym-src/x") == ""
    monkeypatch.delenv("KRYON_BENCH_SKIP_SRC_CHECK", raising=False)

    # No pre-clone / non-container path → nothing to verify.
    assert runner._agent_can_see_source(None) == ""
    assert runner._agent_can_see_source("/some/host/path") == ""
