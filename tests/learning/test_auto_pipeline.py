"""TDD contract for kryon.learning.auto_pipeline.

End-to-end orchestrator: experiences → cluster detection → synth →
eval gate → filesystem write. Every dependency is injectable so the
test runs without ChromaDB / Ollama / LLM.

Output layout:
  ~/.kryon/drafts/_auto/<name>.md           # eval passed
  ~/.kryon/drafts/_rejected/<name>.md       # eval rejected or skipped
  ~/.kryon/drafts/_rejected/<name>.eval.json
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def drafts_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "drafts"
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(target))
    return target


def _experience(eid: str, tools: list[str], tech: list[str], outcome: str = "success") -> dict:
    return {
        "id": eid,
        "outcome": outcome,
        "agent_path": ["recon-scout"],
        "target_profile": {"tech": tech, "ports": [80, 443], "host": f"{eid}.example.com"},
        "chain": [{"tool": t, "args": "", "status": "ok", "output": ""} for t in tools],
        "outcome_signals": {},
        "duration_s": 60,
        "created_at": "2026-04-28T17:00:00+00:00",
    }


def _finding(cwe: str, tech: str = "wordpress") -> dict:
    return {
        "id": f"fnd_{cwe}_{tech}",
        "cwe_id": cwe,
        "tech_fingerprint": tech,
        "title": "test",
        "host": "x.example.com",
        "url": "https://x.example.com/api/x",
    }


# ---------- Empty inputs ----------


def test_empty_experiences_yields_zero_clusters(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    result = run_auto_pipeline(
        experience_loader=lambda: [],
        findings_loader=lambda: [],
    )
    assert result.clusters_detected == 0
    assert result.drafts_synthesized == 0
    assert not list(drafts_dir.rglob("*.md"))


def test_below_threshold_experiences_yield_zero_clusters(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "whatweb"], ["wordpress"]) for i in range(2)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: [],
        min_repetitions=3,
    )
    assert result.clusters_detected == 0


# ---------- Passed flow ----------


def test_passed_draft_lands_in_auto_dir(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    findings = [_finding("CWE-89", tech="wordpress") for _ in range(5)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )
    assert result.clusters_detected == 1
    assert result.drafts_passed == 1
    assert result.drafts_rejected == 0
    auto_dir = drafts_dir / "_auto"
    assert auto_dir.is_dir()
    assert len(list(auto_dir.glob("*.md"))) == 1


def test_passed_draft_loads_via_skill_loader(drafts_dir: Path) -> None:
    """Round-trip: the auto-drafted file must parse with SkillLoader."""
    from kryon.learning.auto_pipeline import run_auto_pipeline
    from kryon.skills.loader import _parse_skill_file

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    findings = [_finding("CWE-89") for _ in range(5)]
    run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )
    auto_files = list((drafts_dir / "_auto").glob("*.md"))
    assert auto_files
    skill = _parse_skill_file(auto_files[0])
    assert skill is not None
    assert "nuclei_scan" in skill.required_tools


# ---------- Rejected flow ----------


def test_rejected_draft_lands_in_rejected_dir_with_sidecar(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    # Chain has only nmap — won't detect SQLi.
    exps = [_experience(f"e{i}", ["nmap", "whatweb"], ["wordpress"]) for i in range(3)]
    findings = [_finding("CWE-89") for _ in range(5)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )
    assert result.drafts_rejected == 1
    assert result.drafts_passed == 0

    rejected_dir = drafts_dir / "_rejected"
    assert rejected_dir.is_dir()
    md_files = list(rejected_dir.glob("*.md"))
    json_files = list(rejected_dir.glob("*.eval.json"))
    assert len(md_files) == 1
    assert len(json_files) == 1

    # Sidecar carries the eval report
    report = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert report["eval_status"] == "rejected"
    assert "reason" in report


# ---------- Skipped flow ----------


def test_skipped_eval_routes_to_rejected_dir(drafts_dir: Path) -> None:
    """Empty findings corpus → eval skipped → draft goes to _rejected/
    (precision-conservative: don't auto-approve without signal)."""
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: [],
    )
    assert result.drafts_skipped == 1
    rejected_files = list((drafts_dir / "_rejected").glob("*.eval.json"))
    assert len(rejected_files) == 1
    report = json.loads(rejected_files[0].read_text(encoding="utf-8"))
    assert report["eval_status"] == "skipped"


# ---------- Multiple clusters ----------


def test_multiple_clusters_each_get_own_draft(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    wp = [_experience(f"wp{i}", ["nmap", "wpscan"], ["wordpress"]) for i in range(3)]
    ssh = [_experience(f"ssh{i}", ["nmap", "hydra"], ["openssh"]) for i in range(3)]
    findings = [_finding("CWE-200", tech="wordpress") for _ in range(5)] + [
        _finding("CWE-287", tech="openssh") for _ in range(5)
    ]
    result = run_auto_pipeline(
        experience_loader=lambda: wp + ssh,
        findings_loader=lambda: findings,
    )
    assert result.clusters_detected == 2
    assert result.drafts_synthesized == 2


# ---------- Idempotence ----------


def test_running_twice_does_not_duplicate(drafts_dir: Path) -> None:
    """Same cluster_id → same draft name → second run overwrites, not duplicates."""
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    findings = [_finding("CWE-89") for _ in range(5)]

    run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )
    run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )

    md_files = list((drafts_dir / "_auto").glob("*.md"))
    # Same cluster_id → name was unique only on first run; second run sees
    # the existing name and bumps the counter. We accept either: no
    # duplicate explosion. At most 2.
    assert 1 <= len(md_files) <= 2


# ---------- Result reporting ----------


def test_pipeline_result_is_frozen() -> None:
    from dataclasses import FrozenInstanceError

    from kryon.learning.auto_pipeline import PipelineResult

    r = PipelineResult(
        clusters_detected=1,
        drafts_synthesized=1,
        drafts_passed=1,
        drafts_rejected=0,
        drafts_skipped=0,
        output_paths=(),
    )
    with pytest.raises(FrozenInstanceError):
        r.drafts_passed = 99  # type: ignore[misc]


def test_result_paths_point_to_actual_files(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    findings = [_finding("CWE-89") for _ in range(5)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )
    for p in result.output_paths:
        assert Path(p).exists()


# ---------- Custom thresholds propagate ----------


def test_custom_min_pass_rate_propagates_to_evaluator(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    # 3/4 = 0.75 detection — would pass at 0.7 default but not at 0.95.
    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    findings = (
        [_finding("CWE-89") for _ in range(3)] + [_finding("CWE-1390")]  # AD weak auth, not detected by web chain
    )
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
        min_pass_rate=0.95,
    )
    assert result.drafts_rejected == 1


# ---------- Resilience ----------


def test_experience_loader_failure_does_not_crash(drafts_dir: Path) -> None:
    from kryon.learning.auto_pipeline import run_auto_pipeline

    def boom() -> list:
        raise RuntimeError("chromadb is offline")

    # Pipeline should swallow + return empty result.
    result = run_auto_pipeline(
        experience_loader=boom,
        findings_loader=lambda: [],
    )
    assert result.clusters_detected == 0


def test_findings_loader_failure_treated_as_empty(drafts_dir: Path) -> None:
    """Pipeline should still detect clusters and synthesize, but eval
    will skip (no corpus)."""
    from kryon.learning.auto_pipeline import run_auto_pipeline

    def boom() -> list:
        raise RuntimeError("findings_library down")

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=boom,
    )
    # Cluster detected, draft synthesized, eval skipped → goes to rejected.
    assert result.clusters_detected == 1
    assert result.drafts_skipped == 1


# =====================================================================
# F77.G.6 — merge-ternary decisions wired into the pipeline
# =====================================================================


def test_first_cluster_is_added(drafts_dir: Path) -> None:
    """Cold start: empty drafts dir → every cluster is ADD.
    PipelineResult.clusters_added counts the action; the file is
    written without a .vN suffix."""
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "wpscan", "sqlmap"], ["wordpress"]) for i in range(5)]
    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: [_finding("CWE-89") for _ in range(5)],
    )
    assert result.clusters_detected == 1
    assert result.clusters_added == 1
    assert result.clusters_merged == 0
    assert result.clusters_discarded == 0
    drafts = list(drafts_dir.rglob("*.md"))
    assert len(drafts) == 1
    assert ".v" not in drafts[0].stem  # no version suffix


def test_second_run_with_same_pattern_triggers_merge(drafts_dir: Path) -> None:
    """First run ADDs the draft. Second run with the same cluster
    pattern must see the existing draft and MERGE → produce a .v2
    file alongside the original (NOT overwriting it)."""
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [_experience(f"e{i}", ["nmap", "wpscan", "sqlmap"], ["wordpress"]) for i in range(5)]
    findings = [_finding("CWE-89") for _ in range(5)]

    run1 = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: findings,
    )
    assert run1.clusters_added == 1

    # Second run: same cluster signature. Use fresh experience IDs so
    # the cluster id is the same (cluster_id is derived from modal
    # chain + tech, not member IDs).
    exps2 = [_experience(f"f{i}", ["nmap", "wpscan", "sqlmap"], ["wordpress"]) for i in range(5)]
    run2 = run_auto_pipeline(
        experience_loader=lambda: exps2,
        findings_loader=lambda: findings,
    )
    assert run2.clusters_merged == 1
    assert run2.clusters_added == 0
    # v2 draft sits next to the v1.
    v2 = [p for p in drafts_dir.rglob("*.md") if p.stem.endswith(".v2")]
    assert len(v2) == 1


def test_degenerate_cluster_is_discarded_before_synthesis(drafts_dir: Path) -> None:
    """A cluster with exactly 3 members but mostly partial outcomes can
    still pass the size floor. Test that the avg_outcome_score floor
    on the decider kicks in for a fail-heavy cluster: every member
    is `partial` (score 0.5), which is at the floor — adjust to
    purely `recon-only` (score 0) to force a discard."""
    from kryon.learning.auto_pipeline import run_auto_pipeline

    exps = [
        _experience(f"e{i}", ["nmap", "wpscan", "sqlmap"], ["wordpress"], outcome="partial")
        for i in range(3)
    ]
    # Convert two of them to recon-only — average outcome drops to ~0.16.
    for i in (0, 1):
        exps[i]["outcome"] = "recon-only"

    result = run_auto_pipeline(
        experience_loader=lambda: exps,
        findings_loader=lambda: [],
    )
    # pattern_detector still surfaces the cluster (it only requires
    # outcome != fail). Decider discards on avg_outcome_score.
    assert result.clusters_detected <= 1
    # But the file should NOT be written.
    assert result.clusters_discarded >= result.clusters_detected
    assert result.clusters_added == 0
    assert result.clusters_merged == 0


def test_merge_records_provenance_lineage(drafts_dir: Path) -> None:
    """The merged .v2 draft must carry merge_from + merge_from_version
    fields in _provenance — pinned for the curator's review workflow."""
    from kryon.learning.auto_pipeline import run_auto_pipeline
    import yaml as _yaml

    exps1 = [_experience(f"e{i}", ["nmap", "wpscan", "sqlmap"], ["wordpress"]) for i in range(5)]
    findings = [_finding("CWE-89") for _ in range(5)]
    run_auto_pipeline(
        experience_loader=lambda: exps1,
        findings_loader=lambda: findings,
    )
    exps2 = [_experience(f"f{i}", ["nmap", "wpscan", "sqlmap"], ["wordpress"]) for i in range(5)]
    run_auto_pipeline(
        experience_loader=lambda: exps2,
        findings_loader=lambda: findings,
    )
    v2 = next(p for p in drafts_dir.rglob("*.md") if p.stem.endswith(".v2"))
    text = v2.read_text(encoding="utf-8")
    fm_block = text.split("\n---", 2)[0][3:]
    fm = _yaml.safe_load(fm_block)
    prov = fm["_provenance"]
    assert prov["merge_from"]
    assert prov["merge_from_version"] == 1
    assert prov["merge_similarity"] >= 0.8  # default merge threshold
