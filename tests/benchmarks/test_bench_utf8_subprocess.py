"""F202.Y — Bench harnesses must use UTF-8 + errors='replace' for
subprocess transcripts.

Background: subprocess.run(..., text=True) on Windows defaults to
cp1252 for stdout decoding. The Kryon container emits UTF-8 (LLM
narration in Spanish, Unicode quotes, emojis from rich panels) which
breaks cp1252 with UnicodeDecodeError mid-bench, killing the run
before any scoring can happen.

This test guards both bench harnesses (CyberGym + htb_bench) by
inspecting the source for the explicit encoding+errors kwargs. We
don't actually invoke docker — that would need the container — but
the regex check prevents regressions where someone removes the
kwargs and the bench fails next Friday on a Spanish-character
transcript.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_htb_bench_runner_uses_utf8_encoding():
    """F202.Y — htb_bench still uses `docker exec ... kryon` for the
    interactive REPL contract (htb-style targets). Verify the
    subprocess.run call passes encoding='utf-8' + errors='replace'
    so Windows cp1252 default doesn't kill the bench on UTF-8
    transcripts.
    """
    runner_path = _REPO_ROOT / "scripts" / "htb_bench" / "runner.py"
    assert runner_path.exists(), f"{runner_path} not found"
    src = runner_path.read_text(encoding="utf-8")
    docker_idx = src.find('"docker", "exec"')
    assert docker_idx != -1, "docker exec invocation not found"
    window = src[docker_idx : docker_idx + 800]
    assert 'encoding="utf-8"' in window
    assert 'errors="replace"' in window


def test_cybergym_runner_uses_rest_api():
    """F202.Z — cybergym pivoted away from `docker exec` REPL to the
    REST API (POST /api/v1/runs) because the CLI requires a
    subcommand and the stdin pipe deadlocked. Guard that the runner
    invokes urllib + the runs endpoint instead of subprocess docker
    exec — the latter is a regression path.
    """
    runner_path = _REPO_ROOT / "scripts" / "cybergym" / "runner.py"
    assert runner_path.exists(), f"{runner_path} not found"
    src = runner_path.read_text(encoding="utf-8")

    # New REST path is required.
    assert "/api/v1/runs" in src, "cybergym must POST to /api/v1/runs"
    assert "X-API-Key" in src, "cybergym must send X-API-Key header"
    assert "urllib.request" in src, "cybergym must use urllib for HTTP"

    # The docker exec pipe is the regression — should not be in
    # invoke_kryon() any more.
    invoke_start = src.find("def invoke_kryon(")
    if invoke_start != -1:
        # Look only at the invoke_kryon function body (~3 kB).
        block = src[invoke_start : invoke_start + 3000]
        assert '"docker", "exec"' not in block, (
            "cybergym invoke_kryon must not shell out to docker exec — "
            "use the REST API."
        )
