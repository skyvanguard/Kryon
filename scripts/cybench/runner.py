"""Run one Cybench task through the Kryon agent and score the transcript.

Reuses the HTB bench's ``kryon investigate --active`` invocation pattern, but sets
the CAPABLE-model profile — the whole point of this bench is to measure V4-Flash
with the harness UN-throttled (KRYON_CAPABLE_MODEL=true), against the frontier
baseline on the same tasks.

Testable offline: ``KRYON_BENCH_DRY_RUN=1`` returns a recorded fixture transcript
so the flow can be exercised without a container or a live model.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from scripts.cybench.loader import CybenchTask
from scripts.cybench.scorer import TaskScore, score_task


def build_prompt(task: CybenchTask, *, hard: bool = True) -> str:
    """Compose the objective handed to the agent: the task prompt + where to look
    (target host for network tasks, the challenge dir for file tasks)."""
    parts = [task.prompt(hard=hard)]
    if task.target_host:
        parts.append(f"\nTarget: {task.target_host}")
    elif task.task_dir is not None:
        parts.append(f"\nChallenge files are in: {task.task_dir.parent / 'challenge'}")
    parts.append("\nReport the flag when you find it.")
    return "".join(parts)


def invoke_kryon(prompt: str, *, timeout: int = 900, model: str | None = None) -> str:
    """Invoke `kryon investigate --active` in the capable profile; return the
    transcript (stdout+stderr). Honors KRYON_BENCH_DRY_RUN / KRYON_BENCH_USE_HOST
    like the HTB bench."""
    if os.environ.get("KRYON_BENCH_DRY_RUN") == "1":
        return os.environ.get("KRYON_BENCH_FIXTURE_TRANSCRIPT", "")

    model = model or os.environ.get("KRYON_BENCH_MODEL", "kryon-local")
    # Capable profile is the DEFAULT measurement condition (V4 un-throttled), but
    # KRYON_CAPABLE_MODEL is overridable so the same harness can run the control
    # arm (capable=false = 4B-regime) for the A/B delta that proves the harness lift.
    common_env = {
        "KRYON_CAPABLE_MODEL": os.environ.get("KRYON_CAPABLE_MODEL", "true"),
        "KRYON_RED_TEAM": os.environ.get("KRYON_RED_TEAM", "true"),
        "KRYON_MODEL": model,
        "KRYON_MODEL_MAX_TOKENS": os.environ.get("KRYON_MODEL_MAX_TOKENS", "1000000"),
        "KRYON_REASONING_EFFORT": os.environ.get("KRYON_REASONING_EFFORT", "medium"),
    }
    invocation = [
        "kryon",
        "investigate",
        prompt,
        "--active",
        "--max-turns",
        os.environ.get("KRYON_BENCH_MAX_TURNS", "15"),
    ]

    if os.environ.get("KRYON_BENCH_USE_HOST") == "1":
        env = {**os.environ, **common_env}
        proc = subprocess.run(
            ["uv", "run", *invocation],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    else:
        docker_env = []
        for k, v in common_env.items():
            docker_env += ["-e", f"{k}={v}"]
        proc = subprocess.run(
            ["docker", "exec", *docker_env, "kryon", *invocation],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


@dataclass(frozen=True)
class RunResult:
    score: TaskScore
    transcript: str


def run_task(task: CybenchTask, *, hard: bool = True, timeout: int = 900, model: str | None = None) -> RunResult:
    """Full flow for one task: build prompt -> invoke agent -> score."""
    prompt = build_prompt(task, hard=hard)
    try:
        transcript = invoke_kryon(prompt, timeout=timeout, model=model)
    except subprocess.TimeoutExpired:
        transcript = f"[TIMEOUT after {timeout}s]"
    return RunResult(score=score_task(transcript, task), transcript=transcript)
