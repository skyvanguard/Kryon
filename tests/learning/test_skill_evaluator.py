"""TDD contract for kryon.learning.skill_evaluator.

The evaluator is the "would this auto-skill have caught past findings"
gate. Stance: precision > recall. We'd rather skip / reject a draft
that's actually fine than approve one that's not.

Three outcomes per evaluation:
  * passed   — pass_rate >= min_pass_rate AND enough findings examined
  * rejected — pass_rate < min_pass_rate
  * skipped  — too few findings to draw a conclusion (cold corpus)
"""

from __future__ import annotations

from typing import Any

import pytest


def _draft_with_tools(tools: list[str], skill_name: str = "auto-test"):
    """Build a SkillDraft directly without going through the synthesizer."""
    from kryon.learning.skill_synthesizer import SkillDraft

    fm = {
        "name": skill_name,
        "description": "test",
        "triggers": {"tech": ["wordpress"], "ports": [80], "keywords": []},
        "priority": 50,
        "required_tools": tools,
        "_provenance": {"cluster_id": "c1", "source": "auto-cluster"},
    }
    return SkillDraft(name=skill_name, body="body", frontmatter=fm)


def _cluster(tech: list[str] | None = None):
    from kryon.learning.pattern_detector import ChainCluster

    return ChainCluster(
        cluster_id="c1",
        member_experience_ids=("e1", "e2", "e3"),
        representative_chain=("nmap", "nuclei_scan"),
        representative_profile={
            "tech": tech if tech is not None else ["wordpress"],
            "ports": [80],
            "sample_hosts": [],
        },
        sample_size=3,
        avg_outcome_score=0.85,
    )


def _finding(
    *,
    cwe: str,
    tech: str = "wordpress",
    severity: str = "high",
    title: str = "test finding",
) -> dict[str, Any]:
    return {
        "id": f"fnd_{cwe}_{tech}",
        "cwe_id": cwe,
        "title": title,
        "severity": severity,
        "tech_fingerprint": tech,
        "url": "https://x.example.com/api/x",
        "host": "x.example.com",
    }


# ---------- EvalReport dataclass ----------


def test_eval_report_is_frozen() -> None:
    from dataclasses import FrozenInstanceError
    from kryon.learning.skill_evaluator import EvalReport

    rep = EvalReport(
        cluster_id="c1",
        eval_status="passed",
        findings_evaluated=10,
        findings_passed=8,
        pass_rate=0.8,
        reason="ok",
    )
    with pytest.raises(FrozenInstanceError):
        rep.pass_rate = 0.5  # type: ignore[misc]


# ---------- Skipped outcomes ----------


def test_skipped_when_findings_corpus_is_empty() -> None:
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=[],
    )
    assert rep.eval_status == "skipped"
    assert "corpus" in rep.reason.lower() or "insufficient" in rep.reason.lower()


def test_skipped_when_relevant_findings_below_minimum() -> None:
    """Even if corpus has 10 findings, if only 1 matches the cluster's
    profile, we skip rather than draw a confident conclusion."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89")]  # only one match
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
    )
    assert rep.eval_status == "skipped"


def test_skipped_does_not_count_as_passed_or_rejected() -> None:
    """The auto pipeline should treat 'skipped' as 'human-review-needed',
    NOT auto-approve. precision > recall posture."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap"]),
        cluster=_cluster(),
        findings=[],
    )
    assert rep.eval_status not in ("passed",)


# ---------- Passed outcome ----------


def test_passed_when_all_findings_match() -> None:
    """SQL injection findings (CWE-89) on wordpress targets — chain
    contains nuclei_scan which detects them → 100% pass rate."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89") for _ in range(5)]
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
    )
    assert rep.eval_status == "passed"
    assert rep.pass_rate == pytest.approx(1.0)
    assert rep.findings_evaluated == 5
    assert rep.findings_passed == 5


def test_passed_with_mixed_outcomes_above_threshold() -> None:
    """4/5 findings detectable by chain → 0.8 > 0.7 default → passed."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = (
        [_finding(cwe="CWE-89") for _ in range(4)]    # detectable by nuclei_scan
        + [_finding(cwe="CWE-1004", title="cookie missing httponly")]  # not in CWE map
    )
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
        min_pass_rate=0.7,
    )
    # CWE-1004 is unknown → it doesn't penalize (precision posture).
    # Only the 4 known CWE-89 findings count, and chain detects all.
    assert rep.eval_status == "passed"


# ---------- Rejected outcome ----------


def test_rejected_when_chain_lacks_detection_tools() -> None:
    """Cluster's chain has only `nmap` + `whatweb` — neither detects SQLi.
    All 5 SQLi findings are NOT detectable → 0/5 → rejected."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89") for _ in range(5)]
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "whatweb"]),  # no SQL detection tool
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
    )
    assert rep.eval_status == "rejected"
    assert rep.pass_rate == 0.0


def test_rejected_when_pass_rate_below_threshold() -> None:
    """2/5 = 0.4 < 0.7 → rejected even though there's coverage."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    # Two SQL findings (detectable by nuclei_scan) + 3 SSRF findings
    # (CWE-1390) which neither nmap nor nuclei_scan covers in our default map.
    findings = (
        [_finding(cwe="CWE-89") for _ in range(2)]
        + [_finding(cwe="CWE-1390") for _ in range(3)]
    )
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
        min_pass_rate=0.7,
    )
    # Override the default CWE map for this test isn't needed — CWE-1390
    # genuinely needs SSRFmap / burp; chain doesn't have it.
    assert rep.eval_status == "rejected"
    assert rep.pass_rate == pytest.approx(0.4)


# ---------- Profile-based filtering ----------


def test_only_relevant_tech_findings_are_evaluated() -> None:
    """Cluster targets WordPress; sharepoint findings shouldn't count."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = (
        [_finding(cwe="CWE-89", tech="wordpress") for _ in range(3)]
        + [_finding(cwe="CWE-89", tech="sharepoint") for _ in range(10)]
    )
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(tech=["wordpress"]),
        findings=findings,
    )
    # Only the 3 wordpress findings counted as relevant.
    assert rep.findings_evaluated == 3


# ---------- Custom thresholds ----------


def test_min_pass_rate_can_be_tightened() -> None:
    """Operator wants 95% confidence — 4/5 (0.8) must be rejected."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89") for _ in range(5)]
    findings.append(_finding(cwe="CWE-1390"))  # 1 AD finding, not detected

    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
        min_pass_rate=0.95,
    )
    # 5/6 = 0.833 — under 0.95 → rejected.
    assert rep.eval_status == "rejected"


def test_min_pass_rate_can_be_relaxed() -> None:
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = (
        [_finding(cwe="CWE-89") for _ in range(2)]
        + [_finding(cwe="CWE-1390") for _ in range(3)]
    )
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
        min_findings_evaluated=3,
        min_pass_rate=0.3,
    )
    assert rep.eval_status == "passed"


# ---------- Custom CWE map ----------


def test_caller_can_inject_custom_cwe_to_tools_map() -> None:
    """Banking compliance teams may have proprietary detection tools."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    custom_map = {"CWE-DEMO-1": {"my_internal_scanner"}}
    findings = [
        {"cwe_id": "CWE-DEMO-1", "tech_fingerprint": "wordpress",
         "id": f"fnd_{i}", "title": "x"}
        for i in range(4)
    ]
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "my_internal_scanner"]),
        cluster=_cluster(),
        findings=findings,
        cwe_to_tools=custom_map,
        min_findings_evaluated=3,
    )
    assert rep.eval_status == "passed"


# ---------- Reason field ----------


def test_passed_report_explains_why() -> None:
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89") for _ in range(5)]
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nuclei_scan", "nmap"]),
        cluster=_cluster(),
        findings=findings,
    )
    assert rep.eval_status == "passed"
    # Human-readable reason
    assert rep.reason
    assert "5" in rep.reason or "100" in rep.reason


def test_rejected_report_explains_what_failed() -> None:
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89") for _ in range(5)]
    rep = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap"]),  # no SQL detector
        cluster=_cluster(),
        findings=findings,
    )
    assert rep.eval_status == "rejected"
    assert rep.reason


# ---------- Determinism ----------


def test_same_inputs_produce_same_report() -> None:
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    findings = [_finding(cwe="CWE-89") for _ in range(5)]
    args = dict(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=findings,
    )
    r1 = evaluate_draft_against_corpus(**args)
    r2 = evaluate_draft_against_corpus(**args)
    assert r1 == r2


# ---------- F77.G.4 — Guide gate integration (relevance + naturalness) ----------


def _good_body(tools: list[str]) -> str:
    """Body that satisfies the Guide axes — long enough, has sections,
    references each tool. Used for tests that need the Guide gate to PASS."""
    tool_lines = "\n".join(f"- Run `{t}` on the target." for t in tools)
    return (
        "## Pre-flight\n"
        "Verify the target host is in scope and the engagement letter is signed.\n\n"
        "## Steps\n"
        f"{tool_lines}\n"
        "Capture findings to ~/.kryon/findings/.\n\n"
        "## Detection\n"
        "Detects exposed admin panels and outdated middleware.\n"
    )


def _draft_with_body(tools: list[str], body: str) -> Any:
    from kryon.learning.skill_synthesizer import SkillDraft

    fm = {
        "name": "guide-test",
        "description": "test",
        "triggers": {"tech": ["wordpress"], "ports": [80], "keywords": []},
        "priority": 50,
        "required_tools": tools,
        "_provenance": {"cluster_id": "c1", "source": "auto-cluster"},
    }
    return SkillDraft(name="guide-test", body=body, frontmatter=fm)


def test_guide_gate_off_by_default_no_guide_score_in_report() -> None:
    """Banking-safe rollout — without the env flag or kwarg, the Guide
    gate doesn't run and `guide_score` stays None."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    report = evaluate_draft_against_corpus(
        draft=_draft_with_tools(["nmap", "nuclei_scan"]),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
    )
    assert report.guide_score is None


def test_guide_gate_kwarg_enables_with_clean_draft_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clean body + correct frontmatter → Guide passes, technical eval runs."""
    monkeypatch.delenv("KRYON_GUIDE_GATE", raising=False)
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    tools = ["nmap", "nuclei_scan"]
    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(tools, _good_body(tools)),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
        apply_guide_gate=True,
    )
    assert report.eval_status == "passed"
    assert report.guide_score is not None
    assert report.guide_score["combined"] >= 0.6


def test_guide_gate_short_circuits_on_broken_draft() -> None:
    """A draft that fails the Guide should skip technical eval entirely."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    # Empty body + matching tools → relevance ~0, naturalness ~0.
    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(["nmap", "nuclei_scan"], body=""),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
        apply_guide_gate=True,
    )
    assert report.eval_status == "rejected_by_guide"
    assert report.guide_score is not None
    assert report.guide_score["combined"] < 0.6
    # Technical eval did NOT run — findings_evaluated stays at 0.
    assert report.findings_evaluated == 0


def test_guide_gate_loop_artifact_rejected() -> None:
    """Generative-loop draft (repeated nonsense + heavy placeholders + no
    section header) gets rejected by Guide before the corpus walk."""
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    body = "TODO TODO TODO XXXX\n" * 30
    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(["nmap"], body=body),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
        apply_guide_gate=True,
    )
    assert report.eval_status == "rejected_by_guide"
    # Reasons should reference both axes (multiple symptoms).
    reasons = report.guide_score["reasons"]
    assert any("relevance:" in r for r in reasons)
    assert any("naturalness:" in r for r in reasons)


def test_guide_gate_env_flag_enables_default_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`KRYON_GUIDE_GATE=true` activates the gate without explicit kwarg."""
    monkeypatch.setenv("KRYON_GUIDE_GATE", "true")
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(["nmap", "nuclei_scan"], body=""),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
    )
    assert report.eval_status == "rejected_by_guide"


def test_guide_gate_threshold_overridable_via_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`KRYON_GUIDE_THRESHOLD=0.95` makes a slightly imperfect draft fail."""
    monkeypatch.setenv("KRYON_GUIDE_THRESHOLD", "0.95")
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    # Draft is good but missing one section → combined ~0.88 (passes 0.6
    # but not 0.95).
    body = "## Steps\n- Run `nmap`.\n- Run `nuclei_scan`.\n" * 3
    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(["nmap", "nuclei_scan"], body=body),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
        apply_guide_gate=True,
    )
    assert report.eval_status == "rejected_by_guide"


def test_guide_gate_invalid_threshold_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Garbled `KRYON_GUIDE_THRESHOLD` doesn't crash — falls back to 0.6."""
    monkeypatch.setenv("KRYON_GUIDE_THRESHOLD", "not-a-float")
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    tools = ["nmap", "nuclei_scan"]
    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(tools, _good_body(tools)),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
        apply_guide_gate=True,
    )
    # Default threshold (0.6) — clean draft passes.
    assert report.eval_status == "passed"


def test_guide_score_payload_shape_is_serializable() -> None:
    """`guide_score` must be a plain dict so it round-trips through json
    when written to `_auto/*.eval.json`."""
    import json

    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus

    tools = ["nmap", "nuclei_scan"]
    report = evaluate_draft_against_corpus(
        draft=_draft_with_body(tools, _good_body(tools)),
        cluster=_cluster(),
        findings=[_finding(cwe="CWE-89") for _ in range(5)],
        apply_guide_gate=True,
    )
    # No exception — guide_score serializes cleanly.
    payload = json.dumps(report.guide_score)
    parsed = json.loads(payload)
    assert set(parsed.keys()) == {"relevance", "naturalness", "combined", "reasons"}
    assert isinstance(parsed["reasons"], list)
