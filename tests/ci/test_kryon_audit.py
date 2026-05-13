"""F89.2 — TDD contract for the CI entrypoint.

Coverage:
  - severity_rank: parametrized over the canonical 5 + unknown
  - filter_failing: gate semantics
  - summarize_findings: bucket counts including unknown bucket
  - write_github_outputs: GITHUB_OUTPUT file path + legacy fallback
  - main(): exit codes (0 clean, 1 gate failed, 2 input error),
    --fail-on=never disables gate, list vs envelope JSON shapes
  - SARIF file produced at the expected path with the expected
    shape
  - Engagement metadata flows into run.properties
  - --include-evidence flag round-trip into SARIF
  - YAML action manifest parses and exposes the documented inputs
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.kryon_audit import (
    SEVERITY_ORDER,
    filter_failing,
    main,
    severity_rank,
    summarize_findings,
    write_github_outputs,
)


# =====================================================================
# Fixtures
# =====================================================================


def _finding(severity: str, *, cwe: str = "CWE-89", url: str = "https://x/api/y") -> dict[str, Any]:
    return {
        "id": f"fnd_{severity.lower()}",
        "cwe_id": cwe,
        "severity": severity,
        "title": f"{severity} finding",
        "url": url,
        "host": "x",
        "url_shape": "https://x/api/N",
        "probe_id": "probe",
        "evidence": "SELECT 1 -- this should NOT appear in SARIF by default",
    }


# =====================================================================
# severity_rank
# =====================================================================


@pytest.mark.parametrize(
    "severity,expected_rank",
    [
        ("info", 0),
        ("low", 1),
        ("medium", 2),
        ("high", 3),
        ("critical", 4),
        ("CRITICAL", 4),  # case-insensitive
        ("  HIGH  ", 3),  # whitespace tolerant
    ],
)
def test_severity_rank_canonical(severity, expected_rank):
    assert severity_rank(severity) == expected_rank


def test_severity_rank_unknown_returns_neg_one():
    """A custom label like 'trivial' or a typo must NOT trigger the
    gate. Returning -1 means filter_failing skips it."""
    assert severity_rank("trivial") == -1
    assert severity_rank("") == -1
    assert severity_rank(None) == -1  # type: ignore[arg-type]


# =====================================================================
# filter_failing
# =====================================================================


def test_filter_failing_high_threshold():
    findings = [_finding(s) for s in ("info", "low", "medium", "high", "critical")]
    failing = filter_failing(findings, "high")
    assert {f["severity"] for f in failing} == {"high", "critical"}


def test_filter_failing_critical_threshold():
    findings = [_finding(s) for s in ("high", "critical", "critical")]
    failing = filter_failing(findings, "critical")
    assert len(failing) == 2  # both criticals


def test_filter_failing_unknown_threshold_returns_empty():
    """Bad fail_on value → gate disabled (empty result). Better than
    crashing the build with an obscure config error."""
    findings = [_finding("critical")]
    assert filter_failing(findings, "garbage") == []


def test_filter_failing_unknown_severity_in_findings_does_not_trigger():
    findings = [{"severity": "trivial"}, _finding("critical")]
    failing = filter_failing(findings, "high")
    # Only the critical fails; the unknown 'trivial' is silent.
    assert len(failing) == 1


# =====================================================================
# summarize_findings
# =====================================================================


def test_summary_counts_canonical_levels():
    findings = [_finding(s) for s in ("info", "low", "low", "medium", "high", "critical")]
    s = summarize_findings(findings)
    assert s["info"] == 1
    assert s["low"] == 2
    assert s["medium"] == 1
    assert s["high"] == 1
    assert s["critical"] == 1
    assert s["unknown"] == 0


def test_summary_includes_unknown_bucket():
    findings = [{"severity": "trivial"}, {"severity": "weird"}]
    s = summarize_findings(findings)
    assert s["unknown"] == 2


def test_summary_handles_empty_list():
    s = summarize_findings([])
    assert all(count == 0 for count in s.values())
    # All canonical keys present.
    assert {*s} == {*SEVERITY_ORDER, "unknown"}


# =====================================================================
# write_github_outputs — env-driven file vs legacy fallback
# =====================================================================


def test_outputs_use_github_output_env_when_set(tmp_path, monkeypatch):
    """Modern runners (post 2023-06-13) set GITHUB_OUTPUT; we append
    to the file."""
    output_file = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    sarif_path = tmp_path / "k.sarif"
    write_github_outputs(
        sarif_path=sarif_path,
        findings=[_finding("critical"), _finding("low")],
        failing=[_finding("critical")],
    )
    contents = output_file.read_text(encoding="utf-8")
    assert f"sarif-path={sarif_path}" in contents
    assert "findings-count=2" in contents
    assert "critical-count=1" in contents
    assert "failing-count=1" in contents


def test_outputs_fallback_to_set_output(monkeypatch, capsys):
    """Pre-2023-06-13 runners didn't set GITHUB_OUTPUT — legacy
    `::set-output::` fallback must still work."""
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    write_github_outputs(
        sarif_path=Path("k.sarif"),
        findings=[_finding("high")],
        failing=[],
    )
    captured = capsys.readouterr()
    assert "::set-output name=sarif-path::k.sarif" in captured.out
    assert "::set-output name=findings-count::1" in captured.out


# =====================================================================
# main() — exit codes + full pipeline
# =====================================================================


def _write_findings(tmp_path: Path, findings: list[dict]) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(findings), encoding="utf-8")
    return p


def test_main_returns_zero_when_no_findings_at_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(tmp_path, [_finding("low"), _finding("medium")])
    sarif_out = tmp_path / "kryon.sarif"
    rc = main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(sarif_out),
            "--fail-on", "high",
        ]
    )
    assert rc == 0
    assert sarif_out.is_file()


def test_main_returns_one_when_gate_triggers(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(
        tmp_path, [_finding("medium"), _finding("critical")]
    )
    rc = main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(tmp_path / "k.sarif"),
            "--fail-on", "high",
        ]
    )
    assert rc == 1


def test_main_never_threshold_disables_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(tmp_path, [_finding("critical")])
    rc = main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(tmp_path / "k.sarif"),
            "--fail-on", "never",
        ]
    )
    assert rc == 0


def test_main_returns_two_on_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    rc = main(
        [
            "--findings", str(tmp_path / "nope.json"),
            "--sarif-out", str(tmp_path / "k.sarif"),
        ]
    )
    assert rc == 2


def test_main_returns_two_on_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    p = tmp_path / "bad.json"
    p.write_text("{not json{", encoding="utf-8")
    rc = main(
        [
            "--findings", str(p),
            "--sarif-out", str(tmp_path / "k.sarif"),
        ]
    )
    assert rc == 2


def test_main_accepts_envelope_shape(tmp_path, monkeypatch):
    """kryon engage emits {"findings": [...]}; the entrypoint must
    accept both that envelope AND a bare list."""
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    p = tmp_path / "envelope.json"
    p.write_text(
        json.dumps({"findings": [_finding("low")], "engagement_id": "x"}),
        encoding="utf-8",
    )
    rc = main(
        [
            "--findings", str(p),
            "--sarif-out", str(tmp_path / "k.sarif"),
            "--fail-on", "high",
        ]
    )
    assert rc == 0


def test_main_drops_non_dict_entries_silently(tmp_path, monkeypatch):
    """If a finding entry is malformed (string, null), drop it
    rather than crash the build."""
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    p = tmp_path / "mixed.json"
    p.write_text(
        json.dumps([_finding("low"), "garbage", None, _finding("critical")]),
        encoding="utf-8",
    )
    rc = main(
        [
            "--findings", str(p),
            "--sarif-out", str(tmp_path / "k.sarif"),
            "--fail-on", "high",
        ]
    )
    assert rc == 1  # critical still fails the gate


# =====================================================================
# SARIF produced has the expected content
# =====================================================================


def test_sarif_output_contains_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(
        tmp_path, [_finding("critical", cwe="CWE-639"), _finding("medium", cwe="CWE-89")]
    )
    sarif_out = tmp_path / "kryon.sarif"
    main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(sarif_out),
            "--fail-on", "never",
        ]
    )
    payload = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"CWE-639", "CWE-89"}
    results = payload["runs"][0]["results"]
    assert len(results) == 2


def test_evidence_redacted_in_sarif_by_default(tmp_path, monkeypatch):
    """Banca-safety: SARIF must NOT carry the evidence body unless
    --include-evidence is explicit."""
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(tmp_path, [_finding("high")])
    sarif_out = tmp_path / "k.sarif"
    main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(sarif_out),
            "--fail-on", "never",
        ]
    )
    blob = sarif_out.read_text(encoding="utf-8")
    assert "SELECT 1" not in blob


def test_evidence_surfaced_when_include_evidence_flag_set(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(tmp_path, [_finding("high")])
    sarif_out = tmp_path / "k.sarif"
    main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(sarif_out),
            "--fail-on", "never",
            "--include-evidence",
        ]
    )
    blob = sarif_out.read_text(encoding="utf-8")
    assert "SELECT 1" in blob


def test_engagement_metadata_flows_to_run_properties(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    findings_file = _write_findings(tmp_path, [_finding("low")])
    sarif_out = tmp_path / "k.sarif"
    main(
        [
            "--findings", str(findings_file),
            "--sarif-out", str(sarif_out),
            "--engagement-id", "eng_2026_42",
            "--client", "BCP",
        ]
    )
    payload = json.loads(sarif_out.read_text(encoding="utf-8"))
    props = payload["runs"][0]["properties"]
    assert props["engagement_id"] == "eng_2026_42"
    assert props["client"] == "BCP"


# =====================================================================
# action.yml manifest sanity
# =====================================================================


def test_action_yml_parses_and_advertises_documented_io():
    """The action.yml is a contract — if a future edit drops one of
    the documented inputs / outputs, downstream workflows break.
    Pin the contract here."""
    import yaml

    manifest_path = Path(__file__).resolve().parents[2] / ".github" / "actions" / "kryon-audit" / "action.yml"
    assert manifest_path.is_file(), f"action manifest missing: {manifest_path}"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    # Top-level shape
    assert manifest["name"]
    assert manifest["description"]
    assert manifest["runs"]["using"] == "composite"

    expected_inputs = {
        "findings",
        "sarif-out",
        "fail-on",
        "upload-sarif",
        "include-evidence",
        "tool-version",
        "engagement-id",
        "client",
    }
    assert expected_inputs <= set(manifest["inputs"].keys())

    expected_outputs = {"sarif-path", "findings-count", "critical-count", "failing-count"}
    assert expected_outputs <= set(manifest["outputs"].keys())

    # `findings` MUST be required — otherwise the gate runs on empty
    # and silently passes.
    assert manifest["inputs"]["findings"]["required"] is True
