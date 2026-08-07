"""Tests for the engage.Finding → SIEM adapter + cron-path dispatch."""

from __future__ import annotations

import json
from dataclasses import dataclass

import kryon.integrations as integrations_mod
from kryon.integrations import IntegrationManager
from kryon.integrations.finding_event import emit_findings_to_siem, finding_to_siem_event


@dataclass
class _Finding:
    cwe: str = ""
    severity: str = ""
    host: str = ""
    rule_id: str = ""
    message: str = ""
    evidence: str = ""
    remediation: str = ""
    target_host: str = ""
    confidence: float = 0.9
    needs_verification: bool = False


def test_finding_to_event_maps_severity_and_delta():
    ev = finding_to_siem_event(
        _Finding(cwe="CWE-89", severity="HIGH", host="10.0.0.5", rule_id="sqli", message="SQL injection"),
        engagement_id="eng1",
        delta="new",
        client="acme",
    )
    assert ev.event_type == "finding"
    assert ev.severity == "high"  # engage UPPER → SIEM lower
    assert ev.metadata["delta"] == "new"
    assert ev.metadata["cwe"] == "CWE-89"
    assert ev.metadata["finding_id"]  # stable fingerprint present
    assert ev.client_id == "acme"


def test_finding_to_event_omits_evidence_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_SIEM_INCLUDE_EVIDENCE", raising=False)
    ev = finding_to_siem_event(
        _Finding(severity="LOW", message="x", evidence="card 4111111111111111"),
        engagement_id="e",
    )
    assert "evidence" not in ev.metadata


def _reset_manager():
    integrations_mod._manager = None


def test_emit_no_op_without_siem_config(monkeypatch):
    monkeypatch.delenv("KRYON_SIEM_TYPE", raising=False)
    _reset_manager()
    n = emit_findings_to_siem([_Finding(severity="HIGH", message="x")], None, engagement_id="e")
    assert n == 0


def test_emit_writes_to_wazuh_file_with_delta(monkeypatch, tmp_path):
    out = str(tmp_path / "findings.json")
    monkeypatch.setenv("KRYON_SIEM_TYPE", "wazuh")
    monkeypatch.setenv("KRYON_SIEM_ENDPOINT", out)
    _reset_manager()

    new_f = _Finding(cwe="CWE-89", severity="HIGH", host="h1", rule_id="sqli", message="new sqli")
    old_f = _Finding(cwe="CWE-79", severity="MEDIUM", host="h2", rule_id="xss", message="known xss")

    # Build a baseline diff where only new_f is NEW.
    from kryon.state.baseline_diff import compute_diff

    diff = compute_diff([old_f], [new_f, old_f])

    n = emit_findings_to_siem([new_f, old_f], diff, engagement_id="eng1", client="acme")
    assert n == 2
    records = [json.loads(line) for line in (tmp_path / "findings.json").read_text(encoding="utf-8").splitlines()]
    by_rule = {r["rule_id"]: r for r in records}
    assert by_rule["sqli"]["delta"] == "new"
    assert by_rule["xss"]["delta"] == "existing"


def test_load_from_env_builds_forwarder(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_SIEM_TYPE", "wazuh")
    monkeypatch.setenv("KRYON_SIEM_ENDPOINT", str(tmp_path / "f.json"))
    monkeypatch.setenv("KRYON_SIEM_MIN_SEVERITY", "high")
    mgr = IntegrationManager()
    mgr.load_from_env()
    assert len(mgr._forwarders) == 1
    assert mgr._forwarders[0].extra.get("min_severity") == "high"


def test_load_from_env_noop_when_unset(monkeypatch):
    monkeypatch.delenv("KRYON_SIEM_TYPE", raising=False)
    mgr = IntegrationManager()
    mgr.load_from_env()
    assert mgr._forwarders == []
