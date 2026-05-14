"""F129 — Cross-engagement audit aggregator tests.

The aggregator walks ``.kryon/audit/*.jsonl`` files and emits a
report with counts (engagements, tool calls, phase outcomes), a
top-N tool usage list, verdict distribution if surfaced into the
audit, redaction totals, and avg duration per phase type. Use:

    from kryon.audit.aggregator import aggregate_audit_logs
    report = aggregate_audit_logs(audit_dir="/.kryon/audit/")
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kryon.audit.aggregator import (
    AggregateReport,
    aggregate_audit_logs,
    format_report,
)


def _write_entry(
    path: Path,
    *,
    timestamp: str,
    engagement_id: str,
    phase: str,
    tool_name: str,
    duration_ms: int = 0,
    status: str = "ok",
    redaction_count: int = 0,
) -> None:
    entry = {
        "timestamp": timestamp,
        "engagement_id": engagement_id,
        "phase": phase,
        "tool_name": tool_name,
        "args_hash": "a" * 64,
        "args_redacted": "{}",
        "result_hash": "b" * 64,
        "result_redacted": "",
        "duration_ms": duration_ms,
        "status": status,
        "redaction_count": redaction_count,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Empty + single-file basics
# ---------------------------------------------------------------------------


def test_empty_directory_returns_zero_report(tmp_path):
    report = aggregate_audit_logs(tmp_path)
    assert report.engagements == 0
    assert report.tool_calls == 0
    assert report.phase_status_counts == {}


def test_single_engagement_counts_calls(tmp_path):
    log = tmp_path / "eng-A.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="A", phase="recon", tool_name="nmap")
    _write_entry(log, timestamp="2026-05-14T10:01:00Z", engagement_id="A", phase="recon", tool_name="curl")
    _write_entry(log, timestamp="2026-05-14T10:02:00Z", engagement_id="A", phase="vuln_scan", tool_name="nuclei")

    report = aggregate_audit_logs(tmp_path)

    assert report.engagements == 1
    assert report.tool_calls == 3


def test_multiple_engagements_counted(tmp_path):
    a = tmp_path / "eng-A.jsonl"
    b = tmp_path / "eng-B.jsonl"
    _write_entry(a, timestamp="2026-05-14T10:00:00Z", engagement_id="A", phase="recon", tool_name="nmap")
    _write_entry(b, timestamp="2026-05-14T11:00:00Z", engagement_id="B", phase="recon", tool_name="nmap")

    report = aggregate_audit_logs(tmp_path)

    assert report.engagements == 2
    assert report.tool_calls == 2


# ---------------------------------------------------------------------------
# Phase status + tool frequency
# ---------------------------------------------------------------------------


def test_phase_status_distribution(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="recon", tool_name="t", status="ok")
    _write_entry(
        log, timestamp="2026-05-14T10:01:00Z", engagement_id="x", phase="vuln_scan", tool_name="t", status="failed"
    )
    _write_entry(
        log, timestamp="2026-05-14T10:02:00Z", engagement_id="x", phase="api_fuzzing", tool_name="t", status="failed"
    )

    report = aggregate_audit_logs(tmp_path)

    assert report.phase_status_counts.get("ok") == 1
    assert report.phase_status_counts.get("failed") == 2


def test_tool_frequency_top_tools(tmp_path):
    log = tmp_path / "eng.jsonl"
    # nmap × 5, nuclei × 3, curl × 1
    for i in range(5):
        _write_entry(log, timestamp=f"2026-05-14T10:00:0{i}Z", engagement_id="x", phase="r", tool_name="nmap")
    for i in range(3):
        _write_entry(log, timestamp=f"2026-05-14T10:01:0{i}Z", engagement_id="x", phase="v", tool_name="nuclei")
    _write_entry(log, timestamp="2026-05-14T10:02:00Z", engagement_id="x", phase="r", tool_name="curl")

    report = aggregate_audit_logs(tmp_path)

    assert report.tool_frequency["nmap"] == 5
    assert report.tool_frequency["nuclei"] == 3
    assert report.tool_frequency["curl"] == 1


def test_top_n_tools_ordered_by_count(tmp_path):
    log = tmp_path / "eng.jsonl"
    for i in range(10):
        _write_entry(log, timestamp=f"2026-05-14T10:00:{i:02d}Z", engagement_id="x", phase="r", tool_name="A")
    for i in range(5):
        _write_entry(log, timestamp=f"2026-05-14T10:01:{i:02d}Z", engagement_id="x", phase="r", tool_name="B")

    report = aggregate_audit_logs(tmp_path)

    top = report.top_tools(2)
    assert top[0] == ("A", 10)
    assert top[1] == ("B", 5)


# ---------------------------------------------------------------------------
# Time-based filtering
# ---------------------------------------------------------------------------


def test_since_filter_excludes_older_entries(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(log, timestamp="2026-05-10T10:00:00Z", engagement_id="x", phase="r", tool_name="t")  # before
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="r", tool_name="t")  # after
    _write_entry(log, timestamp="2026-05-15T10:00:00Z", engagement_id="x", phase="r", tool_name="t")  # after

    report = aggregate_audit_logs(tmp_path, since=datetime(2026, 5, 14, tzinfo=timezone.utc))

    assert report.tool_calls == 2


def test_until_filter_excludes_newer_entries(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="r", tool_name="t")
    _write_entry(log, timestamp="2026-05-15T10:00:00Z", engagement_id="x", phase="r", tool_name="t")
    _write_entry(log, timestamp="2026-05-20T10:00:00Z", engagement_id="x", phase="r", tool_name="t")  # past until

    report = aggregate_audit_logs(tmp_path, until=datetime(2026, 5, 16, tzinfo=timezone.utc))

    assert report.tool_calls == 2


# ---------------------------------------------------------------------------
# Redaction totals + duration
# ---------------------------------------------------------------------------


def test_redaction_totals_summed(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="r", tool_name="t", redaction_count=2)
    _write_entry(log, timestamp="2026-05-14T10:01:00Z", engagement_id="x", phase="r", tool_name="t", redaction_count=5)
    _write_entry(log, timestamp="2026-05-14T10:02:00Z", engagement_id="x", phase="r", tool_name="t", redaction_count=0)

    report = aggregate_audit_logs(tmp_path)

    assert report.total_redactions == 7


def test_avg_duration_per_phase(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(
        log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="recon", tool_name="t", duration_ms=1000
    )
    _write_entry(
        log, timestamp="2026-05-14T10:01:00Z", engagement_id="x", phase="recon", tool_name="t", duration_ms=3000
    )
    _write_entry(
        log, timestamp="2026-05-14T10:02:00Z", engagement_id="x", phase="vuln_scan", tool_name="t", duration_ms=5000
    )

    report = aggregate_audit_logs(tmp_path)

    assert report.avg_duration_ms_per_phase["recon"] == 2000
    assert report.avg_duration_ms_per_phase["vuln_scan"] == 5000


# ---------------------------------------------------------------------------
# Malformed entries are skipped, not crashing
# ---------------------------------------------------------------------------


def test_malformed_lines_are_skipped(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="r", tool_name="t")
    with log.open("a", encoding="utf-8") as fh:
        fh.write("not valid json\n")
        fh.write('{"missing": "fields"}\n')
    _write_entry(log, timestamp="2026-05-14T10:01:00Z", engagement_id="x", phase="r", tool_name="t")

    report = aggregate_audit_logs(tmp_path)

    # The 2 well-formed entries are kept; the 2 malformed lines are skipped.
    assert report.tool_calls == 2


# ---------------------------------------------------------------------------
# format_report — human-readable
# ---------------------------------------------------------------------------


def test_format_report_contains_summary_lines(tmp_path):
    log = tmp_path / "eng-A.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="A", phase="recon", tool_name="nmap")

    report = aggregate_audit_logs(tmp_path)
    text = format_report(report)

    assert "Engagements" in text or "engagements" in text.lower()
    assert "1" in text  # one tool call
    assert "nmap" in text


# ---------------------------------------------------------------------------
# AggregateReport.to_dict for JSON output
# ---------------------------------------------------------------------------


def test_aggregate_report_to_dict_is_json_serializable(tmp_path):
    log = tmp_path / "eng.jsonl"
    _write_entry(log, timestamp="2026-05-14T10:00:00Z", engagement_id="x", phase="r", tool_name="t")

    report = aggregate_audit_logs(tmp_path)
    d = report.to_dict()

    # Round-trip through json to make sure nothing exotic in the structure.
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert parsed["engagements"] == 1
    assert parsed["tool_calls"] == 1
