"""Lynis report.dat → engage.Finding mapping + gate wiring."""

from __future__ import annotations

from kryon.integrations.lynis import normalizer
from kryon.integrations.lynis.normalizer import parse_report, report_to_findings

_REPORT = """
lynis_version=3.0.9
lynis_report_version=1.0
hardening_index=67
warning[]=SSH-7408|Weak SSH configuration|-|
suggestion[]=SSH-7408|Harden SSH: PermitRootLogin YES to NO|-|
suggestion[]=BOOT-5122|Set a GRUB bootloader password|-|
""".strip()


def test_parse_report():
    p = parse_report(_REPORT)
    assert len(p["warnings"]) == 1
    assert len(p["suggestions"]) == 2
    assert p["hardening_index"] == 67


def test_findings_warnings_and_suggestions():
    findings = report_to_findings(_REPORT, host="10.0.0.5", apply_gates=False)
    assert len(findings) == 3
    warn = next(f for f in findings if f.rule_id == "LYNIS-SSH-7408" and f.severity == "MEDIUM")
    assert warn.confidence == 1.0
    assert warn.needs_verification is False
    assert warn.host == "10.0.0.5"
    sugg = next(f for f in findings if f.rule_id == "LYNIS-BOOT-5122")
    assert sugg.severity == "LOW"
    assert sugg.confidence == 0.7
    assert sugg.needs_verification is True


def test_suggestions_can_be_excluded():
    findings = report_to_findings(_REPORT, host="h", apply_gates=False, include_suggestions=False)
    assert len(findings) == 1  # only the warning
    assert findings[0].severity == "MEDIUM"


def test_gates_drop(monkeypatch):
    monkeypatch.setattr(normalizer, "is_cve_applicable_for_finding", lambda f, *, tech_stack: (True, "ok"))
    monkeypatch.setattr(normalizer, "is_finding_applicable_general", lambda f, *, tech_stack: (False, "drop"))
    assert report_to_findings(_REPORT, host="h", tech_stack={"windows"}, apply_gates=True) == []


def test_gates_pass(monkeypatch):
    monkeypatch.setattr(normalizer, "is_cve_applicable_for_finding", lambda f, *, tech_stack: (True, "ok"))
    monkeypatch.setattr(normalizer, "is_finding_applicable_general", lambda f, *, tech_stack: (True, "ok"))
    assert len(report_to_findings(_REPORT, host="h", apply_gates=True)) == 3
