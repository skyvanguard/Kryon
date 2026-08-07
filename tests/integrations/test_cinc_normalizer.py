"""Cinc Auditor JSON report → engage.Finding mapping + gate wiring."""

from __future__ import annotations

from kryon.integrations.cinc import normalizer
from kryon.integrations.cinc.normalizer import impact_to_severity, parse_controls, results_to_findings

_REPORT = """
{"profiles": [{"name": "ssh-baseline", "controls": [
  {"id": "sshd-01", "title": "Set protocol to 2", "desc": "Use SSHv2 only",
   "impact": 1.0, "tags": {"cwe": "CWE-326"},
   "results": [{"status": "failed", "code_desc": "Protocol should eq 2", "message": "got 1"}]},
  {"id": "sshd-05", "title": "Disable root login", "impact": 0.6,
   "results": [{"status": "passed", "code_desc": "PermitRootLogin should eq no"}]},
  {"id": "sshd-10", "title": "MaxAuthTries", "impact": 0.3,
   "results": [{"status": "skipped", "code_desc": "n/a"}]}
]}]}
""".strip()


def test_impact_to_severity_bands():
    assert impact_to_severity(1.0) == "CRITICAL"
    assert impact_to_severity(0.7) == "HIGH"
    assert impact_to_severity(0.5) == "MEDIUM"
    assert impact_to_severity(0.2) == "LOW"
    assert impact_to_severity(0.0) == "INFO"


def test_parse_controls():
    ctrls = parse_controls(_REPORT)
    assert len(ctrls) == 3
    by_id = {c["id"]: c for c in ctrls}
    assert by_id["sshd-01"]["any_failed"] is True
    assert by_id["sshd-05"]["any_failed"] is False
    assert by_id["sshd-10"]["any_failed"] is False
    assert by_id["sshd-01"]["cwe"] == "CWE-326"


def test_only_failed_controls_become_findings():
    findings = results_to_findings(_REPORT, host="10.0.0.5", apply_gates=False)
    assert len(findings) == 1  # only sshd-01 failed
    f = findings[0]
    assert f.rule_id == "CINC-sshd-01"
    assert f.severity == "CRITICAL"  # impact 1.0
    assert f.host == "10.0.0.5"
    assert f.confidence == 1.0
    assert f.needs_verification is False  # deterministic config assertion
    assert f.cwe == "CWE-326"
    assert "SSHv2" in f.remediation
    assert "got 1" in f.evidence


def test_cwe_defaults_when_absent():
    report = '{"profiles":[{"name":"p","controls":[{"id":"c1","title":"t","impact":0.5,"results":[{"status":"failed","code_desc":"x"}]}]}]}'
    findings = results_to_findings(report, apply_gates=False)
    assert findings[0].cwe == "CINC"


def test_gates_drop_nonapplicable(monkeypatch):
    monkeypatch.setattr(normalizer, "is_cve_applicable_for_finding", lambda f, *, tech_stack: (False, "drop"))
    monkeypatch.setattr(normalizer, "is_finding_applicable_general", lambda f, *, tech_stack: (True, "ok"))
    findings = results_to_findings(_REPORT, host="10.0.0.5", tech_stack={"windows"}, apply_gates=True)
    assert findings == []


def test_gates_pass_keeps_finding(monkeypatch):
    monkeypatch.setattr(normalizer, "is_cve_applicable_for_finding", lambda f, *, tech_stack: (True, "ok"))
    monkeypatch.setattr(normalizer, "is_finding_applicable_general", lambda f, *, tech_stack: (True, "ok"))
    findings = results_to_findings(_REPORT, host="10.0.0.5", tech_stack={"linux"}, apply_gates=True)
    assert len(findings) == 1
