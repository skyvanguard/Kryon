"""Tests for retest delta reporting (F1.3)."""

from __future__ import annotations

import json

from kryon.state.retest import build_delta_report, format_delta_summary, write_delta_report


def _f(rule_id, host, severity="high", evidence="ev"):
    return {
        "rule_id": rule_id,
        "host": host,
        "severity": severity,
        "message": "issue",
        "cwe": "CWE-1",
        "remediation": "fix",
        "evidence": evidence,
    }


def test_delta_counts_remediation_progress():
    previous = [_f("R1", "h1"), _f("R2", "h1"), _f("R3", "h1")]
    current = [_f("R1", "h1")]  # R2, R3 remediated; nothing new
    report = build_delta_report(previous, current)
    r = report["remediation"]
    assert r["baseline_total"] == 3
    assert r["remediated"] == 2
    assert r["still_open"] == 1
    assert r["newly_introduced"] == 0
    assert r["progress_pct"] == 66.7


def test_delta_flags_newly_introduced():
    previous = [_f("R1", "h1")]
    current = [_f("R1", "h1"), _f("R9", "h1")]  # R9 is new
    report = build_delta_report(previous, current)
    assert report["remediation"]["newly_introduced"] == 1
    assert report["summary"]["new"] == 1


def test_delta_detects_severity_change():
    previous = [_f("R1", "h1", severity="low")]
    current = [_f("R1", "h1", severity="critical")]  # severity bumped → changed
    report = build_delta_report(previous, current)
    assert report["summary"]["changed"] == 1


def test_format_summary_reads_naturally():
    report = build_delta_report([_f("R1", "h1"), _f("R2", "h1")], [_f("R1", "h1")])
    s = format_delta_summary(report)
    assert "1/2 remediated" in s
    assert "50.0%" in s


def test_write_delta_report_emits_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path / "reports")
    previous = [_f("R1", "h1"), _f("R2", "h1")]
    current = [_f("R1", "h1"), _f("R9", "h1")]  # R2 fixed, R9 new
    report = build_delta_report(previous, current)
    result = write_delta_report(report, tmp_path / "out", client_name="banco_x", fmt="csv")
    assert result["delta_json"].exists()
    assert result["action_sheet"].exists()
    on_disk = json.loads(result["delta_json"].read_text(encoding="utf-8"))
    assert on_disk["remediation"]["remediated"] == 1
    # Action sheet = NEW + CHANGED only (R9). R1 stable is excluded.
    content = result["action_sheet"].read_text(encoding="utf-8-sig")
    assert "R9" in content
    assert "R1" not in content
