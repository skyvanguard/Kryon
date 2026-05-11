"""F81 — Single-target run orchestration.

Given a walkthrough JSON, this module:
  1. Spawns the target (docker-compose up / vagrant up / no-op for url).
  2. Waits for `ready_url` to respond 2xx.
  3. Invokes Kryon with a target-specific prompt.
  4. Captures the tool chain Kryon executed + each tool's output.
  5. Greps captured outputs for any `flag_pattern` regex → pwn=true/false.
  6. Diffs actual chain vs `expected_chain` → chain_match_score.
  7. Tears down the target.

Returns a `RunResult` (frozen dataclass) — purely data; the harness
itself doesn't print. The CLI / reporter consume the result.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# How often to poll `ready_url` while waiting for target spawn.
_READY_POLL_INTERVAL_SECONDS = 2
_READY_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class RunResult:
    """Result of running Kryon against one target."""

    slug: str
    pwn: bool
    chain_match_score: float  # 0..1 (only over `required` steps)
    time_to_pwn_seconds: float | None
    wall_time_seconds: float
    actual_chain: tuple[str, ...] = field(default_factory=tuple)  # tool names
    expected_required: tuple[str, ...] = field(default_factory=tuple)
    chain_extra: tuple[str, ...] = field(default_factory=tuple)
    flag_match_pattern: str | None = None  # which regex matched
    error: str | None = None  # set if spawn/teardown/run errored
    raw_output: str = ""  # captured Kryon transcript (for debug)


def load_walkthrough(path: Path) -> dict[str, Any]:
    """Read and minimally validate a walkthrough JSON."""
    data = json.loads(path.read_text(encoding="utf-8"))
    required_keys = {"slug", "title", "source", "expected_chain", "flag_pattern"}
    missing = required_keys - data.keys()
    if missing:
        raise ValueError(f"walkthrough {path.name} missing keys: {missing}")
    return data


def spawn_target(walkthrough: dict[str, Any]) -> dict[str, Any]:
    """Bring up the target. Returns a `handle` dict the caller passes to
    `teardown_target` later. Idempotent — if target is already up, no-op.

    For the MVP the handle just records what was started so we can stop
    it. Future: track docker compose project name, vagrant box, etc.
    """
    src = walkthrough["source"]
    src_type = src.get("type", "url")

    if src_type == "url":
        # Pre-existing URL (PortSwigger Lab / live target). Nothing to do.
        return {"type": "url", "ref": src["ref"]}

    if src_type == "docker_compose":
        compose_path = Path(src["ref"])
        if not compose_path.exists():
            raise FileNotFoundError(f"compose file not found: {compose_path}")
        # `-d` background; project_name from slug for isolated cleanup.
        project = f"htb_bench_{walkthrough['slug'].replace('-', '_')}"
        subprocess.run(
            ["docker", "compose", "-p", project, "-f", str(compose_path), "up", "-d"],
            check=True, capture_output=True, timeout=120,
        )
        return {"type": "docker_compose", "project": project, "ref": str(compose_path)}

    if src_type == "vagrant_box":
        box_dir = Path(src["ref"])
        subprocess.run(
            ["vagrant", "up"], cwd=box_dir, check=True, capture_output=True, timeout=300,
        )
        return {"type": "vagrant", "ref": str(box_dir)}

    raise ValueError(f"unsupported source type: {src_type}")


def wait_for_ready(walkthrough: dict[str, Any]) -> bool:
    """Poll `ready_url` until 2xx or timeout. Returns False on timeout —
    the caller marks the run as `error="target_not_ready"`."""
    ready_url = walkthrough["source"].get("ready_url")
    if not ready_url:
        return True  # no ready check; trust caller knows what they're doing

    deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            import urllib.request

            with urllib.request.urlopen(ready_url, timeout=3) as resp:
                if 200 <= resp.status < 300:
                    return True
        except Exception:
            pass
        time.sleep(_READY_POLL_INTERVAL_SECONDS)
    return False


def teardown_target(handle: dict[str, Any]) -> None:
    """Best-effort cleanup. Never raises — bench results are more
    important than perfect resource hygiene."""
    try:
        if handle["type"] == "docker_compose":
            subprocess.run(
                ["docker", "compose", "-p", handle["project"],
                 "-f", handle["ref"], "down", "-v"],
                capture_output=True, timeout=60, check=False,
            )
        elif handle["type"] == "vagrant":
            subprocess.run(
                ["vagrant", "halt"], cwd=handle["ref"],
                capture_output=True, timeout=60, check=False,
            )
        # url type: no-op.
    except Exception:
        pass


def parse_chain(transcript: str) -> tuple[str, ...]:
    """Extract the ordered list of tool names from a Kryon transcript.

    Looks for the F77.D Fase 8 invocation glyph: `▸ <tool_name>  <args>`.
    One match per line. Order preserved. Duplicates kept (some chains
    legitimately call run_command twice).
    """
    pattern = re.compile(r"^\s*▸\s+([a-z_][a-z0-9_]*)\b", re.MULTILINE)
    return tuple(pattern.findall(transcript))


def check_flag(transcript: str, patterns: list[str]) -> str | None:
    """Return the first regex pattern that matched the transcript, or
    None when no flag was found."""
    for pat in patterns:
        if re.search(pat, transcript, re.IGNORECASE):
            return pat
    return None


def chain_match(actual: tuple[str, ...], expected_required: list[str]) -> float:
    """Fraction of required tools that appeared in the actual chain.
    Order-independent (we don't penalize different paths to pwn)."""
    if not expected_required:
        return 1.0
    actual_set = set(actual)
    hit = sum(1 for t in expected_required if t in actual_set)
    return hit / len(expected_required)


def invoke_kryon(prompt: str, timeout: int = 600) -> str:
    """Invoke Kryon non-interactively against the target. Captures the
    full transcript (stdout + stderr) for chain extraction.

    The MVP shells out to `docker exec -i kryon kryon` and pipes the
    prompt. If `KRYON_BENCH_DRY_RUN=1`, returns a recorded fixture so
    smoke tests don't need a live container.
    """
    import os

    if os.environ.get("KRYON_BENCH_DRY_RUN") == "1":
        # Smoke-test path — caller injects a fixture via env var.
        return os.environ.get("KRYON_BENCH_FIXTURE_TRANSCRIPT", "")

    proc = subprocess.run(
        ["docker", "exec", "-i", "kryon", "kryon"],
        input=prompt + "\n/exit\n",
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.stdout + "\n" + proc.stderr


def run_target(walkthrough_path: Path, *, prompt_template: str | None = None) -> RunResult:
    """End-to-end: spawn target, run Kryon, score, teardown."""
    walkthrough = load_walkthrough(walkthrough_path)
    slug = walkthrough["slug"]
    expected_required = [
        s["tool"] for s in walkthrough["expected_chain"] if s.get("required")
    ]

    handle = None
    wall_start = time.monotonic()
    transcript = ""
    error = None
    pwn = False
    flag_match = None

    try:
        handle = spawn_target(walkthrough)

        if not wait_for_ready(walkthrough):
            error = "target_not_ready"
            return RunResult(
                slug=slug,
                pwn=False,
                chain_match_score=0.0,
                time_to_pwn_seconds=None,
                wall_time_seconds=time.monotonic() - wall_start,
                expected_required=tuple(expected_required),
                error=error,
            )

        budget = walkthrough.get("wall_budget_seconds", 600)
        prompt = (prompt_template or "Audita este target: {ready_url}").format(
            ready_url=walkthrough["source"].get("ready_url", ""),
            slug=slug,
        )
        transcript = invoke_kryon(prompt, timeout=budget)

        flag_match = check_flag(transcript, walkthrough["flag_pattern"])
        pwn = flag_match is not None
    except subprocess.TimeoutExpired:
        error = "kryon_timeout"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    finally:
        if handle:
            teardown_target(handle)

    actual_chain = parse_chain(transcript)
    score = chain_match(actual_chain, expected_required) if pwn else 0.0
    extras = tuple(t for t in actual_chain if t not in expected_required)

    return RunResult(
        slug=slug,
        pwn=pwn,
        chain_match_score=score,
        time_to_pwn_seconds=(time.monotonic() - wall_start) if pwn else None,
        wall_time_seconds=time.monotonic() - wall_start,
        actual_chain=actual_chain,
        expected_required=tuple(expected_required),
        chain_extra=extras,
        flag_match_pattern=flag_match,
        error=error,
        raw_output=transcript[:5000],  # cap for the report payload
    )
