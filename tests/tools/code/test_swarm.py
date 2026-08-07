"""Tests for hunt_repo_swarm — ARTEMIS swarm as a tool (gap #1).

_run_swarm (which clones + spawns hunters) is monkeypatched, so no git, no
compiler, no network is needed.
"""

from __future__ import annotations

from kryon.skills.planner_hunter import HuntReport
from kryon.tools.code import swarm as swarm_mod
from kryon.tools.code.swarm import _fmt_report, _swarm_impl


def _report(**kw) -> HuntReport:
    base = dict(
        repo_url="github.com/foo/bar",
        repo_path="/tmp/bar",
        head_sha="abc123def456",
        duration_s=12.3,
        files_scored=10,
        hunters_spawned=5,
        raw_findings=3,
        confirmed_findings=1,
        rejected_findings=2,
        verdicts=[
            {"verdict": "CONFIRMED", "cwe": "CWE-787", "file": "parse.c", "line": 88, "title": "oob write"},
            {"verdict": "REJECTED", "cwe": "CWE-120", "file": "x.c", "line": 5},
        ],
        parallelism=2,
        runner_type="heuristic",
    )
    base.update(kw)
    return HuntReport(**base)


# --- guards -----------------------------------------------------------------


def test_empty_repo_url():
    assert _swarm_impl("").startswith("ERROR")


def test_gate_off(monkeypatch):
    monkeypatch.delenv("KRYON_ZERODAY_VERIFY", raising=False)
    out = _swarm_impl("github.com/foo/bar")
    assert "OFF" in out
    assert "hunt_zero_days" in out  # points at the read-only alternative


# --- formatting -------------------------------------------------------------


def test_fmt_surfaces_confirmed():
    out = _fmt_report(_report())
    assert "Hunt Report" in out
    assert "✅ 1 confirmados" in out
    assert "CWE-787" in out
    assert "parse.c:88" in out


def test_fmt_no_confirmed():
    out = _fmt_report(_report(verdicts=[{"verdict": "REJECTED"}]))
    assert "Ningún finding confirmado" in out


# --- full impl --------------------------------------------------------------


def test_swarm_runs_and_formats(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    monkeypatch.setattr(swarm_mod, "_run_swarm", lambda *a, **k: _report())
    out = _swarm_impl("github.com/foo/bar", budget=5)
    assert "✅ 1 confirmados" in out


def test_swarm_exception_surfaced(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")

    def boom(*a, **k):
        raise RuntimeError("clone failed")

    monkeypatch.setattr(swarm_mod, "_run_swarm", boom)
    out = _swarm_impl("github.com/foo/bar")
    assert out.startswith("ERROR during swarm hunt")
    assert "clone failed" in out


# --- wiring -----------------------------------------------------------------


def test_registered_and_offered():
    from pathlib import Path

    import yaml

    from kryon.skills.tool_budget import build_tool_registry

    assert "hunt_repo_swarm" in build_tool_registry()
    assert swarm_mod.hunt_repo_swarm.name == "hunt_repo_swarm"
    md = Path(__file__).resolve().parents[3] / "src/kryon/skills/playbooks/zero-day/zero-day-hunter.md"
    fm = yaml.safe_load(md.read_text(encoding="utf-8").split("---")[1])
    assert "hunt_repo_swarm" in fm["required_tools"]
