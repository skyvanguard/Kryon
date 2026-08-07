"""F105 — TDD contract for the HTTP smuggling analyzer."""

from __future__ import annotations

import pytest

from kryon.tools.api.http_smuggling import (
    ALL_SMG_RULES,
    SmugglingAnalysis,
    SmugglingFinding,
    SmugglingProbe,
    _classify_probe,
    _embedded_response_count,
    analyze_probes,
)


def _probe(
    probe_type: str = "",
    status: int = 200,
    rt: float = 0.1,
    body: str = "",
    extras: int = 0,
) -> SmugglingProbe:
    return SmugglingProbe(
        probe_type=probe_type,
        http_status=status,
        response_time_seconds=rt,
        body_fingerprint=body,
        additional_responses_observed=extras,
    )


# =====================================================================
# Embedded response counting
# =====================================================================


def test_embedded_response_count_zero():
    assert _embedded_response_count("<html>plain body</html>") == 0


def test_embedded_response_count_one():
    body = "garbage\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n"
    assert _embedded_response_count(body) == 1


def test_embedded_response_count_multiple():
    body = "HTTP/1.1 200 OK\n\n\nHTTP/1.0 404 Not Found\n"
    assert _embedded_response_count(body) == 2


# =====================================================================
# Each rule POSITIVE + NEGATIVE
# =====================================================================


def test_smg_001_cl_te_with_embedded_response_critical():
    body = "...\nHTTP/1.1 200 OK\nContent-Type: text/html\n\nleaked"
    findings = _classify_probe(_probe("cl.te", body=body))
    assert any(f.rule_id == "SMG-001" and f.severity == "CRITICAL" for f in findings)


def test_smg_001_cl_te_clean_silent():
    findings = _classify_probe(_probe("cl.te", body="<html>200 ok</html>"))
    assert not any(f.rule_id == "SMG-001" for f in findings)


def test_smg_002_te_cl_critical():
    findings = _classify_probe(_probe("te.cl", extras=1))
    assert any(f.rule_id == "SMG-002" for f in findings)


def test_smg_003_te_te_high():
    body = "HTTP/1.1 400 Bad Request\nContent-Length: 0\n\n"
    findings = _classify_probe(_probe("te.te", body=body))
    assert any(f.rule_id == "SMG-003" and f.severity == "HIGH" for f in findings)


def test_smg_004_te_zero_critical():
    findings = _classify_probe(_probe("te.0", extras=2))
    assert any(f.rule_id == "SMG-004" and f.severity == "CRITICAL" for f in findings)


def test_smg_004_te_zero_alt_name():
    findings = _classify_probe(_probe("te.zero", extras=1))
    assert any(f.rule_id == "SMG-004" for f in findings)


def test_smg_005_both_headers_high():
    findings = _classify_probe(_probe("both-headers", status=200))
    assert any(f.rule_id == "SMG-005" and f.severity == "HIGH" for f in findings)


def test_smg_005_both_headers_rejected_silent():
    """If server returned 400 on both-headers probe, that's correct
    behavior — no finding."""
    findings = _classify_probe(_probe("both-headers", status=400))
    assert not any(f.rule_id == "SMG-005" for f in findings)


def test_smg_006_timing_evidence_medium():
    findings = _classify_probe(_probe("te-timing", rt=6.2))
    assert any(f.rule_id == "SMG-006" and f.severity == "MEDIUM" for f in findings)


def test_smg_006_fast_timing_silent():
    findings = _classify_probe(_probe("te-timing", rt=0.4))
    assert not any(f.rule_id == "SMG-006" for f in findings)


def test_smg_007_h2_downgrade_high():
    findings = _classify_probe(_probe("h2-downgrade", extras=1))
    assert any(f.rule_id == "SMG-007" and f.severity == "HIGH" for f in findings)


def test_smg_008_unknown_probe_with_fragmentation_low():
    body = "HTTP/1.1 200 OK\n\n"
    findings = _classify_probe(_probe("weird-probe-name", body=body))
    assert any(f.rule_id == "SMG-008" and f.severity == "LOW" for f in findings)


def test_unknown_probe_clean_silent():
    findings = _classify_probe(_probe("weird-probe-name", body="plain body"))
    assert not any(f.rule_id == "SMG-008" for f in findings)


# =====================================================================
# Aggregation
# =====================================================================


def test_analyze_probes_empty():
    analysis = analyze_probes([])
    assert analysis.total_probes == 0
    assert analysis.findings == ()


def test_analyze_probes_sorts_by_severity():
    probes = [
        _probe("te-timing", rt=7.0),  # MEDIUM
        _probe("cl.te", body="HTTP/1.1 200 OK\n\n"),  # CRITICAL
        _probe("te.te", body="HTTP/1.1 200 OK\n\n"),  # HIGH
    ]
    analysis = analyze_probes(probes)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


# =====================================================================
# Pin + frozen
# =====================================================================


def test_all_rules_pinned():
    expected = {f"SMG-{n:03d}" for n in range(1, 9)}
    assert expected == ALL_SMG_RULES


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    p = SmugglingProbe(probe_type="cl.te")
    with pytest.raises(FrozenInstanceError):
        p.probe_type = "te.cl"  # type: ignore[misc]
