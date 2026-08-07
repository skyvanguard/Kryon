"""Tests for cross-host engagement consolidation (F1.1)."""

from __future__ import annotations

import json

from kryon.reporting.consolidate import (
    collect_host_findings,
    consolidate_engagement_dir,
    consolidate_rows,
    segment_summary,
)


def _write_host(root, item_id, host, findings):
    d = root / item_id
    d.mkdir(parents=True)
    (d / f"kryon-{item_id}.findings.json").write_text(
        json.dumps({"context": {"target_scope": host, "engagement_id": item_id}, "findings": findings}),
        encoding="utf-8",
    )


def _finding(rule_id, severity, message="issue", host="", cwe="CWE-000"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "cwe": cwe,
        "host": host,
        "target_host": host,
        "remediation": "fix it",
        "evidence": "evidence",
    }


def test_collect_host_findings(tmp_path):
    _write_host(tmp_path, "itm-1", "10.0.0.1", [_finding("R1", "high")])
    _write_host(tmp_path, "itm-2", "10.0.0.2", [_finding("R2", "low"), _finding("R3", "critical")])
    hosts = collect_host_findings(tmp_path)
    assert len(hosts) == 2
    assert {h.host for h in hosts} == {"10.0.0.1", "10.0.0.2"}


def test_skips_dirs_without_findings(tmp_path):
    (tmp_path / "empty").mkdir()
    _write_host(tmp_path, "itm-1", "10.0.0.1", [_finding("R1", "high")])
    hosts = collect_host_findings(tmp_path)
    assert len(hosts) == 1


def test_consolidate_rows_populates_host(tmp_path):
    _write_host(tmp_path, "itm-1", "10.0.0.9", [_finding("R1", "medium", host="")])
    hosts = collect_host_findings(tmp_path)
    rows = consolidate_rows(hosts)
    assert rows[0].host == "10.0.0.9"  # filled from engagement context


def test_segment_summary_aggregates(tmp_path):
    _write_host(tmp_path, "itm-1", "10.0.0.1", [_finding("R1", "high")])
    _write_host(tmp_path, "itm-2", "10.0.0.2", [_finding("R2", "low"), _finding("R3", "critical")])
    hosts = collect_host_findings(tmp_path)
    rows = consolidate_rows(hosts)
    summary = segment_summary(hosts, rows)
    assert summary["host_count"] == 2
    assert summary["total_findings"] == 3
    assert summary["by_severity"]["CRITICAL"] == 1
    assert len(summary["hash"]) == 64  # sha256 hex


def test_summary_hash_is_deterministic(tmp_path):
    _write_host(tmp_path, "itm-1", "10.0.0.1", [_finding("R1", "high")])
    hosts = collect_host_findings(tmp_path)
    rows = consolidate_rows(hosts)
    h1 = segment_summary(hosts, rows)["hash"]
    h2 = segment_summary(hosts, rows)["hash"]
    assert h1 == h2


def test_consolidate_engagement_dir_writes_deliverable(tmp_path, monkeypatch):
    # Keep the spreadsheet inside tmp_path.
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path / "reports")
    _write_host(tmp_path, "itm-1", "10.0.0.1", [_finding("R1", "high")])
    _write_host(tmp_path, "itm-2", "10.0.0.2", [_finding("R2", "critical")])
    result = consolidate_engagement_dir(tmp_path, client_name="banco_x", fmt="csv")
    assert result["spreadsheet"].exists()
    assert result["summary_json"].exists()
    assert result["summary"]["total_findings"] == 2
    on_disk = json.loads(result["summary_json"].read_text(encoding="utf-8"))
    assert on_disk["host_count"] == 2
