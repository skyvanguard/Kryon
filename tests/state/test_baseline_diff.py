"""F133 — Baseline diffing tests."""

from __future__ import annotations

import json
from pathlib import Path

from kryon.state.baseline_diff import (
    BaselineDiff,
    compute_diff,
    format_diff_summary,
    load_previous_findings,
)


def _f(rule_id: str, host: str = "x", severity: str = "MEDIUM", evidence: str = "") -> dict:
    return {"rule_id": rule_id, "host": host, "severity": severity, "evidence": evidence}


# ---------------------------------------------------------------------------
# compute_diff buckets
# ---------------------------------------------------------------------------


def test_empty_previous_means_all_new():
    curr = [_f("A"), _f("B")]
    diff = compute_diff([], curr)
    assert len(diff.new) == 2
    assert diff.gone == []
    assert diff.stable == []
    assert diff.changed == []


def test_none_previous_treated_as_empty():
    curr = [_f("A")]
    diff = compute_diff(None, curr)
    assert len(diff.new) == 1


def test_identical_findings_are_stable():
    prev = [_f("A"), _f("B")]
    curr = [_f("A"), _f("B")]
    diff = compute_diff(prev, curr)
    assert len(diff.stable) == 2
    assert diff.new == []
    assert diff.gone == []
    assert diff.changed == []


def test_new_finding_appears_in_new_bucket():
    prev = [_f("A")]
    curr = [_f("A"), _f("B")]
    diff = compute_diff(prev, curr)
    assert len(diff.new) == 1
    assert diff.new[0]["rule_id"] == "B"
    assert len(diff.stable) == 1


def test_disappeared_finding_in_gone_bucket():
    prev = [_f("A"), _f("B")]
    curr = [_f("A")]
    diff = compute_diff(prev, curr)
    assert len(diff.gone) == 1
    assert diff.gone[0]["rule_id"] == "B"


def test_severity_bump_is_change():
    prev = [_f("A", severity="MEDIUM")]
    curr = [_f("A", severity="HIGH")]
    diff = compute_diff(prev, curr)
    assert len(diff.changed) == 1
    assert diff.changed[0]["previous"]["severity"] == "MEDIUM"
    assert diff.changed[0]["current"]["severity"] == "HIGH"


def test_evidence_change_is_change():
    prev = [_f("A", evidence="response 200")]
    curr = [_f("A", evidence="response 500 with stack trace")]
    diff = compute_diff(prev, curr)
    assert len(diff.changed) == 1


def test_evidence_whitespace_only_difference_is_stable():
    prev = [_f("A", evidence="response 200")]
    curr = [_f("A", evidence="response   200")]
    diff = compute_diff(prev, curr)
    assert len(diff.stable) == 1
    assert diff.changed == []


def test_same_rule_different_host_are_distinct():
    prev = [_f("A", host="host1")]
    curr = [_f("A", host="host2")]
    diff = compute_diff(prev, curr)
    # rule_id same, but host different → A@host1 gone, A@host2 new
    assert len(diff.gone) == 1
    assert len(diff.new) == 1
    assert diff.stable == []


# ---------------------------------------------------------------------------
# BaselineDiff helpers
# ---------------------------------------------------------------------------


def test_has_changes_true_when_new():
    diff = compute_diff([], [_f("A")])
    assert diff.has_changes is True


def test_has_changes_false_when_all_stable():
    diff = compute_diff([_f("A")], [_f("A")])
    assert diff.has_changes is False


def test_to_dict_includes_summary():
    diff = compute_diff([_f("A")], [_f("A"), _f("B")])
    d = diff.to_dict()
    assert d["summary"]["new"] == 1
    assert d["summary"]["stable"] == 1


# ---------------------------------------------------------------------------
# load_previous_findings
# ---------------------------------------------------------------------------


def test_load_previous_missing_path_returns_empty():
    assert load_previous_findings(None) == []
    assert load_previous_findings("") == []
    assert load_previous_findings("/no/such/file") == []


def test_load_previous_reads_object_shape(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps({"findings": [_f("A")]}), encoding="utf-8")
    loaded = load_previous_findings(p)
    assert len(loaded) == 1
    assert loaded[0]["rule_id"] == "A"


def test_load_previous_reads_array_shape(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps([_f("A"), _f("B")]), encoding="utf-8")
    loaded = load_previous_findings(p)
    assert len(loaded) == 2


def test_load_previous_handles_malformed_json(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text("not json", encoding="utf-8")
    assert load_previous_findings(p) == []


# ---------------------------------------------------------------------------
# format_diff_summary
# ---------------------------------------------------------------------------


def test_format_no_changes():
    diff = compute_diff([_f("A")], [_f("A")])
    text = format_diff_summary(diff)
    assert "no changes" in text.lower()


def test_format_with_changes():
    diff = compute_diff([_f("A")], [_f("A", severity="HIGH"), _f("B")])
    text = format_diff_summary(diff)
    assert "NEW" in text and "CHANGED" in text


# ---------------------------------------------------------------------------
# Finding dataclass coercion
# ---------------------------------------------------------------------------


def test_compute_diff_accepts_dataclass_findings():
    from dataclasses import dataclass

    @dataclass
    class F:
        rule_id: str
        host: str = "x"
        severity: str = "MEDIUM"
        evidence: str = ""

    prev = [F(rule_id="A")]
    curr = [F(rule_id="A"), F(rule_id="B")]
    diff = compute_diff(prev, curr)
    assert len(diff.new) == 1
    assert len(diff.stable) == 1
