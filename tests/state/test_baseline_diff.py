"""F133 — Baseline diffing tests."""

from __future__ import annotations

import json
from pathlib import Path

from kryon.state.baseline_diff import (
    BaselineDiff,
    _canonicalize_evidence,
    _normalize_host,
    baseline_exists,
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


# ---------------------------------------------------------------------------
# R1 — evidence canonicalization (Fase 1: domar el ruido)
#
# The diff must not flip a finding to `changed` when the ONLY thing that
# moved is a volatile token: a timestamp, a session id, a uptime counter.
# Those change every run and would drown the operator in false drift.
# ---------------------------------------------------------------------------


def test_canonicalize_masks_iso_timestamp():
    a = _canonicalize_evidence("scan at 2026-07-07T03:14:22Z ok")
    b = _canonicalize_evidence("scan at 2026-07-01T22:09:00Z ok")
    assert a == b


def test_canonicalize_masks_date_and_clock():
    a = _canonicalize_evidence("last seen 2026-07-07 03:14:22")
    b = _canonicalize_evidence("last seen 2026-01-02 11:59:01")
    assert a == b


def test_canonicalize_masks_uuid():
    a = _canonicalize_evidence("session 3f2504e0-4f89-41d3-9a0c-0305e82c3301 open")
    b = _canonicalize_evidence("session 550e8400-e29b-41d4-a716-446655440000 open")
    assert a == b


def test_canonicalize_masks_long_hex_token():
    a = _canonicalize_evidence("token a1b2c3d4e5f60718293a4b5c6d7e8f90")
    b = _canonicalize_evidence("token ffeeddccbbaa00112233445566778899")
    assert a == b


def test_canonicalize_masks_uptime():
    a = _canonicalize_evidence("system up 14 days, 3:22")
    b = _canonicalize_evidence("system up 2 days, 0:01")
    assert a == b


def test_canonicalize_preserves_real_content():
    # A genuine status change must survive canonicalization.
    a = _canonicalize_evidence("HTTP 200 on /admin")
    b = _canonicalize_evidence("HTTP 500 on /admin")
    assert a != b


def test_evidence_differing_only_by_timestamp_is_stable():
    prev = [_f("A", evidence="banner captured 2026-07-01T00:00:00Z")]
    curr = [_f("A", evidence="banner captured 2026-07-07T03:14:22Z")]
    diff = compute_diff(prev, curr)
    assert len(diff.stable) == 1
    assert diff.changed == []


def test_evidence_differing_only_by_session_id_is_stable():
    prev = [_f("A", evidence="sid=3f2504e0-4f89-41d3-9a0c-0305e82c3301")]
    curr = [_f("A", evidence="sid=550e8400-e29b-41d4-a716-446655440000")]
    diff = compute_diff(prev, curr)
    assert len(diff.stable) == 1


def test_evidence_real_change_still_flagged_despite_timestamp():
    prev = [_f("A", evidence="2026-07-01T00:00:00Z HTTP 200")]
    curr = [_f("A", evidence="2026-07-07T03:14:22Z HTTP 500")]
    diff = compute_diff(prev, curr)
    assert len(diff.changed) == 1


# ---------------------------------------------------------------------------
# R2 — host key normalization (Fase 1)
#
# Same host written two ways (case, port, scheme, trailing dot) must map to
# the same diff key, or a formatting wobble produces a phantom gone+new pair.
# ---------------------------------------------------------------------------


def test_normalize_host_lowercases():
    assert _normalize_host("Host.Example.COM") == "host.example.com"


def test_normalize_host_strips_port():
    assert _normalize_host("10.0.0.5:8080") == "10.0.0.5"


def test_normalize_host_strips_scheme_and_path():
    assert _normalize_host("https://web.local:443/admin?x=1") == "web.local"


def test_normalize_host_strips_trailing_dot():
    assert _normalize_host("fqdn.internal.") == "fqdn.internal"


def test_normalize_host_preserves_ipv6():
    # Bracketed IPv6 with a port → strip the port, keep the address.
    assert _normalize_host("[2001:db8::1]:8443") == "2001:db8::1"


def test_host_with_and_without_port_are_same_finding():
    prev = [_f("A", host="10.0.0.5")]
    curr = [_f("A", host="10.0.0.5:8080")]
    diff = compute_diff(prev, curr)
    assert len(diff.stable) == 1
    assert diff.new == []
    assert diff.gone == []


def test_host_case_difference_is_same_finding():
    prev = [_f("A", host="Web.Local")]
    curr = [_f("A", host="web.local")]
    diff = compute_diff(prev, curr)
    assert len(diff.stable) == 1


def test_genuinely_different_hosts_stay_distinct():
    prev = [_f("A", host="10.0.0.5")]
    curr = [_f("A", host="10.0.0.6")]
    diff = compute_diff(prev, curr)
    assert len(diff.gone) == 1
    assert len(diff.new) == 1


# ---------------------------------------------------------------------------
# R3 — baseline_exists: distinguish "no baseline yet" from "empty baseline"
#
# First-ever run (no file) → warm-up, stay silent. A file that exists but
# holds an empty list means the previous run was clean, so new findings ARE
# real drift and must alert.
# ---------------------------------------------------------------------------


def test_baseline_exists_false_for_missing():
    assert baseline_exists(None) is False
    assert baseline_exists("") is False
    assert baseline_exists("/no/such/file.json") is False


def test_baseline_exists_true_for_present_even_when_empty(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert baseline_exists(p) is True


def test_baseline_exists_true_for_present_array(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps([_f("A")]), encoding="utf-8")
    assert baseline_exists(p) is True
