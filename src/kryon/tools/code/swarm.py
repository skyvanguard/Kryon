"""hunt_repo_swarm — the ARTEMIS swarm as an agentic tool (gap #1).

Kryon's most powerful hunter, ``planner_hunter.hunt_zero_days`` (clone a git
repo → priority-score → spawn N parallel hunters with a supervisor + budget →
ASAN-verified findings), was reachable ONLY via the ``/hunt`` REPL command. The
agent couldn't launch it. This exposes it as a tool so the operator can say
"cazá zero-days en github.com/foo/bar" and the model runs the whole swarm.

Differs from ``hunt_zero_days`` (tools/code/hunt.py): that one is single-pass
reasoning over a LOCAL tree; this clones a REMOTE repo and runs the multi-hunter
swarm with the ASAN oracle — much heavier, much more thorough.

Safety: it clones untrusted code AND executes PoCs (compiles with ASAN, runs
them), so it's gated behind ``KRYON_ZERODAY_VERIFY`` — same contract as the rest
of the execution stack, and it must run inside the container's isolation.

The swarm is async; the agent may already be inside an event loop, so we run it
in a dedicated worker thread with its own loop (asyncio.run in the caller loop
would raise "loop already running").
"""

from __future__ import annotations

import os

from kryon.sdk.agents import function_tool


def _gate_on() -> bool:
    return os.environ.get("KRYON_ZERODAY_VERIFY", "").strip().lower() in ("1", "true", "yes", "on")


def _fmt_report(report) -> str:
    """Render a HuntReport as markdown, surfacing ASAN-confirmed findings."""
    try:
        summary = report.pretty()
    except Exception:  # noqa: BLE001 — never let formatting sink a real result
        summary = f"Hunt report for {getattr(report, 'repo_url', '?')}"
    out = ["```", summary, "```", ""]
    verdicts = getattr(report, "verdicts", None) or []
    confirmed = [v for v in verdicts if str(v.get("verdict", "")).upper() == "CONFIRMED"]
    if confirmed:
        out.append(f"## ✅ {len(confirmed)} confirmados (crash bajo ASAN)")
        for v in confirmed:
            loc = f"{v.get('file', '?')}:{v.get('line', '?')}"
            desc = v.get("title") or v.get("description") or ""
            out.append(f"- **{v.get('cwe', '')}** `{loc}` — {desc}")
    else:
        out.append("_Ningún finding confirmado por ASAN en este run._")
    return "\n".join(out)


def _run_swarm(repo_url: str, budget: int, runner_type: str, ref: str):
    """Run the async swarm in a dedicated thread + loop. Returns a HuntReport."""
    import asyncio
    import concurrent.futures

    from kryon.skills.planner_hunter import hunt_zero_days as _swarm

    def _work():
        return asyncio.run(_swarm(repo_url, budget=budget, runner_type=runner_type, ref=ref))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_work).result()


def _swarm_impl(repo_url: str, budget: int = 10, runner_type: str = "heuristic", ref: str = "") -> str:
    """Implementation, separated from the function_tool wrapper for tests."""
    if not repo_url or not repo_url.strip():
        return "ERROR: repo_url is empty"
    if not _gate_on():
        return (
            "The ARTEMIS swarm is OFF. Set KRYON_ZERODAY_VERIFY=true to run it — it clones "
            "the repo and executes ASAN-verified PoCs, so it stays gated + inside the container. "
            "For a read-only reasoned review of LOCAL code, use hunt_zero_days instead."
        )
    try:
        report = _run_swarm(repo_url.strip(), budget=budget, runner_type=runner_type, ref=ref)
    except Exception as e:  # noqa: BLE001 — surface to the model, don't crash the turn
        return f"ERROR during swarm hunt: {type(e).__name__}: {e}"
    return _fmt_report(report)


@function_tool(strict_mode=False)
def hunt_repo_swarm(repo_url: str, budget: int = 10, runner_type: str = "heuristic", ref: str = "") -> str:
    """Hunt zero-days across a whole git REPO with the ARTEMIS multi-hunter swarm.

    Use this when the operator asks to hunt/audit an entire remote repository for
    vulnerabilities ("cazá zero-days en github.com/foo/bar", "auditá este repo").
    It clones the repo, ranks files by attack surface, spawns parallel hunters
    with a supervisor and budget, and confirms memory bugs with AddressSanitizer
    (a crash is proof). Heavier and far more thorough than hunt_zero_days (which
    is a single-pass reasoned review of a LOCAL tree).

    Args:
        repo_url: git URL of the target repository.
        budget: max files to hunt, top-N by attack-surface priority (default 10).
        runner_type: "heuristic" (fast, deterministic, default) or "llm"
            (reasoning hunters — slower, needs the model).
        ref: optional git branch/tag/sha to check out after clone.

    Returns a markdown report: files scored, hunters spawned, ASAN-confirmed vs
    rejected findings, and the confirmed vulnerabilities. Requires
    KRYON_ZERODAY_VERIFY=true (it clones and executes PoCs).
    """
    return _swarm_impl(repo_url, budget, runner_type, ref)
