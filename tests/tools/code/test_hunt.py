"""Tests for hunt_zero_days — the agentic zero-day hunt tool.

The source-review + verification loop are monkeypatched, so no model, no
compiler, no network is needed. Also asserts the tool is registered and
offered by the zero-day-hunter skill (the wiring that makes it agentic).
"""

from __future__ import annotations

import dataclasses

import pytest

from kryon.intelligence.source_review import SourceFinding, SourceReviewResult
from kryon.tools.code import hunt as hunt_mod
from kryon.tools.code.hunt import _fmt_findings, _gate_on, _hunt_impl


def _finding(**kw) -> SourceFinding:
    base = dict(
        file="src/parser.c",
        line=42,
        cwe="CWE-787",
        severity="HIGH",
        title="out-of-bounds write",
        description="unbounded index",
        evidence="buf[i]=0;",
        sink="buf[i]",
        confidence=0.8,
    )
    base.update(kw)
    return SourceFinding(**base)


# --- gate -------------------------------------------------------------------


def test_gate_off_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_ZERODAY_VERIFY", raising=False)
    assert _gate_on() is False


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "on"])
def test_gate_on_values(monkeypatch, val):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", val)
    assert _gate_on() is True


# --- formatting -------------------------------------------------------------


def test_fmt_confirmed_and_novel():
    f = _finding(verified=True, verification_verdict="confirmed", crash_type="heap-buffer-overflow", novelty_verdict="likely-novel")
    out = "\n".join(_fmt_findings([f], verified_loop=True))
    assert "✅ CONFIRMED" in out
    assert "🎯 NOVEL" in out
    assert "heap-buffer-overflow" in out


def test_fmt_known_cve():
    f = _finding(novelty_verdict="likely-known", nearest_cve="CVE-2019-1234")
    out = "\n".join(_fmt_findings([f], verified_loop=False))
    assert "known (CVE-2019-1234)" in out


def test_fmt_unverified_plain():
    out = "\n".join(_fmt_findings([_finding()], verified_loop=False))
    assert "unverified" in out
    assert "CWE-787" in out


# --- _hunt_impl -------------------------------------------------------------


def test_missing_path_errors():
    out = _hunt_impl("/no/such/path/xyz")
    assert out.startswith("ERROR")
    assert "does not exist" in out


def test_review_results_formatted(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text("int main(){}")
    import kryon.intelligence.source_review as sr

    result = SourceReviewResult(findings=[_finding()], files_reviewed=1, files_total=1, elapsed_seconds=0.5)
    monkeypatch.setattr(sr, "review_tree", lambda *a, **k: result)
    monkeypatch.setattr(sr, "LocalReviewer", lambda *a, **k: object())

    out = _hunt_impl(str(tmp_path), verify=False)
    assert "Zero-day hunt" in out
    assert "1 findings" in out
    assert "CWE-787" in out


def test_verify_without_gate_notes_it(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text("code")
    monkeypatch.delenv("KRYON_ZERODAY_VERIFY", raising=False)
    import kryon.intelligence.source_review as sr

    result = SourceReviewResult(findings=[_finding()], files_reviewed=1, files_total=1)
    monkeypatch.setattr(sr, "review_tree", lambda *a, **k: result)
    monkeypatch.setattr(sr, "LocalReviewer", lambda *a, **k: object())

    out = _hunt_impl(str(tmp_path), verify=True)
    assert "Verification loop OFF" in out


def test_verify_with_gate_runs_loop(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text("code")
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    import kryon.intelligence.source_review as sr
    import kryon.intelligence.zeroday_verify as zv

    result = SourceReviewResult(findings=[_finding()], files_reviewed=1, files_total=1)
    monkeypatch.setattr(sr, "review_tree", lambda *a, **k: result)
    monkeypatch.setattr(sr, "LocalReviewer", lambda *a, **k: object())
    # the loop just confirms the finding
    confirmed = dataclasses.replace(_finding(), verified=True, verification_verdict="confirmed", novelty_verdict="likely-novel")
    monkeypatch.setattr(zv, "build_default_loop", lambda root: (lambda fs: [confirmed]))

    out = _hunt_impl(str(tmp_path), verify=True)
    assert "✅ CONFIRMED" in out
    assert "CONFIRMED+NOVEL" in out  # from the summary line


def test_no_findings_message(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text("code")
    import kryon.intelligence.source_review as sr

    monkeypatch.setattr(sr, "review_tree", lambda *a, **k: SourceReviewResult(files_total=3))
    monkeypatch.setattr(sr, "LocalReviewer", lambda *a, **k: object())
    out = _hunt_impl(str(tmp_path), verify=False)
    assert "No vulnerabilities surfaced" in out


def test_review_exception_is_surfaced(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text("code")
    import kryon.intelligence.source_review as sr

    def boom(*a, **k):
        raise RuntimeError("model down")

    monkeypatch.setattr(sr, "review_tree", boom)
    monkeypatch.setattr(sr, "LocalReviewer", lambda *a, **k: object())
    out = _hunt_impl(str(tmp_path), verify=False)
    assert out.startswith("ERROR during source review")
    assert "model down" in out


# --- wiring: registered + offered by the skill ------------------------------


def test_tool_object_is_a_function_tool():
    assert hasattr(hunt_mod.hunt_zero_days, "name")
    assert hunt_mod.hunt_zero_days.name == "hunt_zero_days"
    assert hasattr(hunt_mod.hunt_zero_days, "params_json_schema")


def test_registered_in_tool_registry():
    from kryon.skills.tool_budget import build_tool_registry

    registry = build_tool_registry()
    assert "hunt_zero_days" in registry


def test_offered_by_zeroday_hunter_skill():
    from pathlib import Path

    import yaml

    md = Path(__file__).resolve().parents[3] / "src/kryon/skills/playbooks/zero-day/zero-day-hunter.md"
    text = md.read_text(encoding="utf-8")
    fm = yaml.safe_load(text.split("---")[1])
    assert "hunt_zero_days" in fm["required_tools"]
