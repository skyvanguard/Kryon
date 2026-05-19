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


@pytest.mark.parametrize(
    "runner_path",
    [
        _REPO_ROOT / "scripts" / "cybergym" / "runner.py",
        _REPO_ROOT / "scripts" / "htb_bench" / "runner.py",
    ],
)
def test_bench_runner_uses_utf8_encoding(runner_path):
    """Verify the `docker exec ... kryon` invocation passes
    encoding='utf-8' AND errors='replace' so the bench survives
    Windows cp1252 + UTF-8 transcripts.
    """
    assert runner_path.exists(), f"{runner_path} not found"
    src = runner_path.read_text(encoding="utf-8")

    # Find the subprocess.run call that shells out to the kryon container.
    # We look for the docker exec ... kryon pattern and verify the
    # encoding+errors kwargs appear within ~500 chars of it.
    docker_idx = src.find('"docker", "exec"')
    assert docker_idx != -1, "docker exec invocation not found"

    # Window forward to find the closing paren of subprocess.run.
    window = src[docker_idx : docker_idx + 800]
    assert 'encoding="utf-8"' in window, (
        f"Missing encoding='utf-8' in {runner_path.name}. "
        "subprocess.run defaults to cp1252 on Windows, which breaks "
        "on UTF-8 transcripts."
    )
    assert 'errors="replace"' in window, (
        f"Missing errors='replace' in {runner_path.name}. "
        "Without it, a single rogue byte kills the bench mid-run."
    )
