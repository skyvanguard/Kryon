"""Tests for tabular findings export (CSV / Excel)."""

from __future__ import annotations

import csv
from types import SimpleNamespace

import pytest

from kryon.reporting.findings_export import (
    COLUMNS,
    FindingRow,
    export_findings,
    from_check_result,
    from_engage_finding,
    from_intel_finding,
)


def _check_result(**kw):
    base = dict(
        control_id="PCI-2.2.2",
        control_title="Default vendor accounts disabled",
        section="2",
        verdict="fail",
        severity="high",
        evidence_command="grep root",
        evidence_stdout="root login enabled",
        remediation_static="Disable default accounts.",
        host="10.0.0.5",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_from_check_result_maps_fields():
    row = from_check_result(_check_result(), framework="pci_dss")
    assert row.id == "PCI-2.2.2"
    assert row.severity == "HIGH"  # upper-cased
    assert row.status == "FAIL"  # verdict upper-cased
    assert row.framework == "pci_dss"
    assert row.remediation.startswith("Disable")
    assert row.evidence == "root login enabled"


def test_from_engage_finding_maps_fields():
    finding = SimpleNamespace(
        rule_id="HDR-693",
        message="Missing security headers",
        severity="medium",
        cwe="CWE-693",
        host="",
        target_host="example.com",
        remediation="Add CSP + HSTS.",
        evidence="no CSP header",
    )
    row = from_engage_finding(finding)
    assert row.id == "HDR-693"
    assert row.control == "CWE-693"
    assert row.host == "example.com"  # falls back to target_host
    assert row.status == "OPEN"


def test_evidence_is_capped():
    row = from_check_result(_check_result(evidence_stdout="x" * 2000))
    assert len(row.evidence) <= 500


def test_export_csv_roundtrips(tmp_path, monkeypatch):
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path)
    rows = [from_check_result(_check_result(), framework="pci_dss")]
    path = export_findings(rows, fmt="csv", client_name="banco_x")
    assert path.exists() and path.suffix == ".csv"
    with path.open(encoding="utf-8-sig") as fh:
        parsed = list(csv.DictReader(fh))
    assert list(parsed[0].keys()) == list(COLUMNS)
    assert parsed[0]["id"] == "PCI-2.2.2"
    assert parsed[0]["severity"] == "HIGH"


def test_export_rejects_bad_format(tmp_path, monkeypatch):
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path)
    with pytest.raises(ValueError, match="unsupported export format"):
        export_findings([], fmt="pdf")


def test_export_xlsx_has_findings_and_summary_sheets(tmp_path, monkeypatch):
    openpyxl = pytest.importorskip("openpyxl")
    monkeypatch.setattr("kryon.reporting.findings_export._REPORTS_DIR", tmp_path)
    rows = [
        from_check_result(_check_result(severity="critical"), framework="pci_dss"),
        from_check_result(_check_result(control_id="PCI-1.2.1", severity="low")),
    ]
    path = export_findings(rows, fmt="xlsx", client_name="banco_x")
    assert path.exists() and path.suffix == ".xlsx"
    wb = openpyxl.load_workbook(path)
    assert "Findings" in wb.sheetnames
    assert "Summary" in wb.sheetnames
    findings = wb["Findings"]
    assert [c.value for c in findings[1]] == [c.upper() for c in COLUMNS]
    # 1 header + 2 data rows
    assert findings.max_row == 3
    summary = wb["Summary"]
    total_row = [r for r in summary.iter_rows(values_only=True) if r[0] == "TOTAL"][0]
    assert total_row[1] == 2


def test_from_intel_finding_maps_fields():
    finding = SimpleNamespace(
        id="F-001",
        title="SQL injection in login",
        severity="critical",
        tool_source="sqlmap",
        cve="CVE-2024-1234",
        mitre="T1190",
        affected_asset="app.bank.test",
        validation_status="confirmed",
        remediation="Use parameterized queries.",
        evidence="payload ' OR 1=1",
    )
    row = from_intel_finding(finding)
    assert row.id == "F-001"
    assert row.severity == "CRITICAL"
    assert row.control == "CVE-2024-1234"
    assert row.host == "app.bank.test"
    assert row.status == "CONFIRMED"
    assert row.framework == "sqlmap"


def test_finding_row_as_dict_is_complete():
    row = FindingRow(*(["x"] * len(COLUMNS)))
    assert set(row.as_dict().keys()) == set(COLUMNS)
