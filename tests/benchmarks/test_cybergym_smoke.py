"""F86 — Smoke tests for the CyberGym benchmark harness.

We pin:
  * Walkthrough schema (required keys) and the bundled 3 example tasks.
  * subset_30.yaml manifest shape.
  * Runner detection heuristics (CWE / file / line) on synthetic
    transcripts so we don't need a live Kryon container.
  * Scorer math (Wilson lower bound + detection rate + FPR).
  * End-to-end aggregate over 3 fixture results.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.cybergym.loader import TaskInvalid, load_subset, load_walkthrough
from scripts.cybergym.runner import (
    RunResult,
    _detect_cwe,
    _detect_file,
    _detect_line,
    build_prompt,
    run_task,
)
from scripts.cybergym.scorer import BenchmarkReport, aggregate, wilson_lower_bound

_BENCH_ROOT = Path(__file__).resolve().parent / "cybergym"
_TASKS_DIR = _BENCH_ROOT / "tasks"
_SUBSET_PATH = _BENCH_ROOT / "subset_30.yaml"


# =====================================================================
# Loader
# =====================================================================


def test_subset_manifest_loads():
    tasks = load_subset(_SUBSET_PATH)
    assert isinstance(tasks, list)
    assert len(tasks) >= 3
    assert all("slug" in t for t in tasks)


def test_subset_manifest_has_three_ready_tasks():
    """Sprint 1 contract — the harness ships with at least 3 'ready'
    tasks proving end-to-end. If someone marks them all 'wip', the
    --status ready default returns 0 targets and the CLI confuses
    operators."""
    tasks = load_subset(_SUBSET_PATH)
    ready = [t for t in tasks if t.get("status") == "ready"]
    assert len(ready) >= 3, f"only {len(ready)} ready tasks in subset_30"


def test_three_bundled_walkthroughs_parse():
    for slug in ("log4shell", "heartbleed", "struts2-ognl"):
        wt = load_walkthrough(_TASKS_DIR / f"{slug}.json")
        assert wt["slug"] == slug
        assert wt["cve_id"].startswith("CVE-")
        assert wt["expected_cwe"].startswith("CWE-")


def test_walkthrough_missing_required_key_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"slug": "x", "cve_id": "CVE-0-0"}), encoding="utf-8")
    with pytest.raises(TaskInvalid) as exc:
        load_walkthrough(bad)
    assert "expected_cwe" in exc.value.missing
    assert "source" in exc.value.missing


def test_subset_manifest_without_tasks_key_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"subset": {"name": "x"}}), encoding="utf-8")
    with pytest.raises(TaskInvalid):
        load_subset(bad)


# =====================================================================
# Runner heuristics
# =====================================================================


def test_detect_cwe_positive():
    """A transcript containing CWE-502 anywhere should match the
    expected CWE-502."""
    matched, seen = _detect_cwe("Found CWE-502 in JndiLookup.java", "CWE-502")
    assert matched
    assert seen == ("CWE-502",)


def test_detect_cwe_numeric_alias():
    """The matcher must tolerate "CWE 502", "CWE_502" — Kryon emits
    different spacings depending on the skill."""
    matched, _ = _detect_cwe("the finding is CWE 502, deserialization", "CWE-502")
    assert matched
    matched2, _ = _detect_cwe("category cwe_502 confirmed", "CWE-502")
    assert matched2


def test_detect_cwe_wrong_cwe_is_miss_but_recorded():
    """Wrong CWE → no detection, but the actual CWEs found are
    surfaced so a reviewer sees the near-miss."""
    matched, seen = _detect_cwe("flagged CWE-89 here", "CWE-502")
    assert not matched
    assert "CWE-89" in seen


def test_detect_cwe_dedup_preserves_order():
    """If the agent mentions the same CWE three times, the report
    should not include it three times."""
    _, seen = _detect_cwe("CWE-79 found. Also CWE-79. And again CWE-79", "CWE-79")
    assert seen == ("CWE-79",)


def test_detect_file_substring_match():
    expected = "ssl/d1_both.c"
    text = "vuln located at /usr/local/src/openssl-1.0.1/ssl/d1_both.c:1437"
    matched, hits = _detect_file(text, expected)
    assert matched
    assert any("d1_both.c" in h for h in hits)


def test_detect_file_basename_only_match():
    """Sometimes the agent only names the basename; basename-suffix
    match should still count."""
    matched, _ = _detect_file("see parser.c lines 12-20", "src/proto/parser.c")
    assert matched


def test_detect_file_no_match():
    matched, _ = _detect_file("nothing relevant here", "ssl/d1_both.c")
    assert not matched


def test_detect_file_none_expected_short_circuits():
    """When expected_file is None we cannot match — keep returning
    False without exploring the transcript."""
    matched, hits = _detect_file("some text with parser.c in it", None)
    assert not matched
    assert hits == ()


def test_detect_line_within_tolerance():
    assert _detect_line("at line 1440", 1437, tolerance=5)
    assert _detect_line("at line 1435", 1437, tolerance=5)
    assert not _detect_line("at line 1450", 1437, tolerance=5)


def test_detect_line_skips_when_expected_none():
    assert not _detect_line("at line 100", None)


def test_build_prompt_does_not_leak_cve_id_or_target_file():
    """F202.AB updated contract:

    The CVE id (CVE-2021-44228) MUST stay out of the prompt — it's
    the answer for the specific bench task.

    The expected_file (JndiLookup.java) MUST stay out — that's also
    the answer.

    The CWE family id (CWE-502) IS now allowed in the prompt because
    F202.AB injects classification guidance skills (cwe-502-deserialization)
    that legitimately mention the family. This is consistent with a
    real-world audit where the expert already knows CWE families —
    classification is training, not target-specific spoilers.

    Spoiler-safe contract (post F202.AB):
      - target CVE id: BLOCKED
      - target expected_file basename: BLOCKED
      - target expected_line: BLOCKED
      - CWE family id (e.g. 'CWE-502'): ALLOWED (classification training)
      - sink patterns / methodology: ALLOWED (training)
    """
    wt = load_walkthrough(_TASKS_DIR / "log4shell.json")
    prompt = build_prompt(wt)
    # Target-specific spoilers — still BLOCKED.
    assert "CVE-2021-44228" not in prompt
    assert "JndiLookup.java" not in prompt
    # The audit instruction format is preserved.
    assert "CWE" in prompt
    assert "log4j" in prompt  # project name — public hint, allowed


def test_runner_uses_dry_run_fixture(monkeypatch):
    """End-to-end RunResult against a fixture transcript — proves the
    runner chain (invoke → detect_cwe → detect_file → detect_line)
    wires through correctly without needing the kryon container."""
    monkeypatch.setenv("KRYON_BENCH_DRY_RUN", "1")
    fake_transcript = (
        "Analysis of log4j-core/.../JndiLookup.java reveals CWE-502 deserialization on line 58 of JndiLookup.java"
    )
    monkeypatch.setenv("KRYON_BENCH_FIXTURE_TRANSCRIPT", fake_transcript)

    result = run_task(_TASKS_DIR / "log4shell.json")
    assert result.slug == "log4shell"
    assert result.cve_id == "CVE-2021-44228"
    assert result.cwe_match
    assert result.file_match
    assert result.line_match  # 58 within ±5 of 56
    assert result.detected
    assert result.error is None


def test_runner_records_error_on_timeout(monkeypatch):
    """When invoke_kryon raises, the error is recorded, the run
    doesn't crash the harness, and detected=False."""
    import subprocess

    def _raise(*_, **__):
        raise subprocess.TimeoutExpired("kryon", 1)

    monkeypatch.setattr("scripts.cybergym.runner.invoke_kryon", _raise)

    result = run_task(_TASKS_DIR / "heartbleed.json")
    assert not result.detected
    assert result.error == "kryon_timeout"


def test_runresult_is_frozen():
    rr = RunResult(
        slug="x",
        cve_id="CVE-0-0",
        detected=True,
        cwe_match=True,
        file_match=True,
        line_match=True,
        wall_time_seconds=1.0,
        expected_cwe="CWE-79",
    )
    with pytest.raises((AttributeError, Exception)):
        rr.slug = "y"  # type: ignore[misc]


# =====================================================================
# Scorer
# =====================================================================


def test_wilson_lower_bound_zero_observations():
    assert wilson_lower_bound(0, 0) == 0.0


def test_wilson_lower_bound_full_success():
    """30/30 detections — point estimate is 1.0, Wilson lower bound
    is < 1.0 (this is the value of Wilson: it never collapses to 1)."""
    lb = wilson_lower_bound(30, 30)
    assert 0.85 < lb < 1.0


def test_wilson_lower_bound_half():
    """15/30 — point estimate 0.5, Wilson 95% lower bound ≈ 0.33."""
    lb = wilson_lower_bound(15, 30)
    assert math.isclose(lb, 0.331, abs_tol=0.02)


def test_wilson_lower_bound_matches_skill_scorer():
    """The bench scorer must agree with src/kryon/learning/skill_scorer
    on the SAME inputs. If skill_scorer changes implementation, this
    catches the drift."""
    try:
        from kryon.learning.skill_scorer import wilson_lower_bound as ref

        assert math.isclose(wilson_lower_bound(7, 10), ref(7, 10), abs_tol=1e-9)
    except ImportError:
        pytest.skip("skill_scorer not importable in this env")


def _result(slug: str, *, detected: bool, cwe: bool, file_: bool, extras: tuple[str, ...] = ()) -> RunResult:
    return RunResult(
        slug=slug,
        cve_id="CVE-0-0",
        detected=detected,
        cwe_match=cwe,
        file_match=file_,
        line_match=False,
        wall_time_seconds=5.0,
        expected_cwe="CWE-79",
        actual_cwes_found=(("CWE-79",) if cwe else ()) + extras,
    )


def test_aggregate_basic_counts():
    results = [
        _result("a", detected=True, cwe=True, file_=True),
        _result("b", detected=False, cwe=True, file_=False),  # CWE-only partial
        _result("c", detected=False, cwe=False, file_=True),  # file-only partial
    ]
    tasks: dict[str, dict[str, Any]] = {
        "a": {"category": "injection"},
        "b": {"category": "injection"},
        "c": {"category": "memory_corruption"},
    }
    report = aggregate(results, tasks)
    assert report.total_tasks == 3
    assert report.detected == 1
    assert math.isclose(report.detection_rate, 1 / 3, abs_tol=1e-6)
    assert math.isclose(report.cwe_only_rate, 1 / 3, abs_tol=1e-6)
    assert math.isclose(report.file_only_rate, 1 / 3, abs_tol=1e-6)


def test_aggregate_false_positive_rate():
    """A result that mentions BOTH the expected CWE and an extra CWE
    counts as a false positive (extra CWE was named in error)."""
    results = [
        _result("a", detected=True, cwe=True, file_=True, extras=("CWE-89",)),
        _result("b", detected=True, cwe=True, file_=True),  # clean
    ]
    report = aggregate(results, {"a": {}, "b": {}})
    assert math.isclose(report.false_positive_rate, 0.5, abs_tol=1e-6)


def test_aggregate_by_category_breakdown():
    results = [
        _result("a", detected=True, cwe=True, file_=True),
        _result("b", detected=True, cwe=True, file_=True),
        _result("c", detected=False, cwe=False, file_=False),
    ]
    tasks = {
        "a": {"category": "injection"},
        "b": {"category": "injection"},
        "c": {"category": "memory_corruption"},
    }
    report = aggregate(results, tasks)
    assert report.by_category["injection"]["detection_rate"] == 1.0
    assert report.by_category["memory_corruption"]["detection_rate"] == 0.0
    assert report.by_category["injection"]["wilson_lower_95"] > 0


def test_benchmark_report_is_frozen():
    report = BenchmarkReport(
        total_tasks=1,
        detected=1,
        detection_rate=1.0,
        wilson_lower_95=0.0,
        cwe_only_rate=0.0,
        file_only_rate=0.0,
        false_positive_rate=0.0,
        median_wall_seconds=None,
    )
    with pytest.raises((AttributeError, Exception)):
        report.total_tasks = 99  # type: ignore[misc]


# =====================================================================
# CLI surface
# =====================================================================


def test_cli_resolves_walkthrough_path():
    from scripts.cybergym.cli import _resolve_walkthrough

    p = _resolve_walkthrough("log4shell")
    assert p.exists()
    assert p.name == "log4shell.json"


def test_cli_main_no_tasks_returns_two(monkeypatch, tmp_path):
    """No selection → return code 2 + helpful stderr. Matches HTB bench
    behaviour."""
    from scripts.cybergym import cli

    monkeypatch.setattr(cli, "_BENCH_ROOT", tmp_path)  # empty dir → no tasks
    rc = cli.main(["--all"])
    assert rc == 2


def test_payload_serializes_via_asdict():
    """The CLI calls asdict(report) and json.dumps(...) on the result.
    Frozen dataclasses are asdict-friendly; this test guards against
    accidental non-serializable fields."""
    rr = _result("x", detected=True, cwe=True, file_=True)
    blob = json.dumps(asdict(rr))
    parsed = json.loads(blob)
    assert parsed["slug"] == "x"
    assert parsed["detected"] is True


# =====================================================================
# Reporter
# =====================================================================


def _sample_payload() -> dict[str, Any]:
    """Minimal payload shape the reporter must accept end-to-end."""
    results = [
        _result("a", detected=True, cwe=True, file_=True),
        _result("b", detected=False, cwe=True, file_=False),
        _result("c", detected=False, cwe=False, file_=True),
    ]
    tasks = {
        "a": {"category": "injection"},
        "b": {"category": "injection"},
        "c": {"category": "memory_corruption"},
    }
    report = aggregate(results, tasks)
    return {
        "report": asdict(report),
        "results": [asdict(r) for r in results],
        "subset": "30",
    }


def test_reporter_renders_self_contained_html(tmp_path):
    """HTML must be inline (no external CSS link, no script tags) so
    GitHub Pages can serve it without a build step."""
    from scripts.cybergym.reporter import render_html

    rendered = render_html(_sample_payload())
    assert "<!doctype html>" in rendered
    assert "<style>" in rendered  # inline CSS
    assert "<link" not in rendered.lower()  # no external CSS link
    assert "<script" not in rendered.lower()  # no external JS
    assert "Wilson 95%" in rendered  # vocabulary matches scorer


def test_reporter_escapes_html_in_slugs():
    """A malicious slug like `<script>alert(1)</script>` must not
    survive into the rendered HTML."""
    from scripts.cybergym.reporter import render_html

    rr = _result("<script>x</script>", detected=True, cwe=True, file_=True)
    payload = {
        "report": asdict(aggregate([rr], {"<script>x</script>": {"category": "x"}})),
        "results": [asdict(rr)],
        "subset": "30",
    }
    rendered = render_html(payload)
    # The escaped form must appear; the raw form must not.
    assert "&lt;script&gt;" in rendered
    assert "<script>x</script>" not in rendered


def test_reporter_writes_file(tmp_path):
    from scripts.cybergym.reporter import write_report

    out = tmp_path / "scoreboard.html"
    result = write_report(_sample_payload(), out)
    assert result == out
    assert out.is_file()
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
