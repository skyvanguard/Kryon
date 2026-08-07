"""Tests for program_metrics — the validated → validated-exploitable funnel."""

from __future__ import annotations

from kryon.services.program_metrics import compute_program_metrics


def test_empty():
    m = compute_program_metrics([])
    assert m["total"] == 0
    assert m["validated"] == 0
    assert m["validated_exploitable"] == 0
    assert m["validated_rate"] == 0.0
    assert m["fix_verification_rate"] == 0.0
    assert [s["count"] for s in m["funnel"]] == [0, 0, 0, 0]  # 4 stages


def test_validated_vs_exploitable_split():
    # The XBOW distinction: a confirmed cookie flag (CWE-1004) is VALIDATED but
    # not EXPLOITABLE; a confirmed SQLi (CWE-89) is both.
    records = [
        {"cwe": "CWE-89", "verification_level": "confirmed", "needs_verification": False, "status": "open"},
        {"cwe": "CWE-1004", "verification_level": "confirmed", "needs_verification": False, "status": "open"},
        {"cwe": "CWE-639", "verification_level": "judge-confirmed", "needs_verification": False, "status": "open"},
        {"cwe": "CWE-89", "verification_level": "inferred", "needs_verification": True, "status": "open"},
    ]
    m = compute_program_metrics(records)
    assert m["total"] == 4
    # validated = confirmed/judge-confirmed & not needs_verif → 3 (sqli, cookie, idor)
    assert m["validated"] == 3
    # exploitable = validated AND cwe reaches impact → sqli + idor = 2 (cookie is inert)
    assert m["validated_exploitable"] == 2
    assert m["validated_rate"] == round(2 / 4, 3)  # headline % tracks exploitable
    assert m["validated_ground_truth_rate"] == round(3 / 4, 3)


def test_judge_confirmed_band_and_counts_as_validated():
    records = [
        {"cwe": "CWE-89", "verification_level": "judge-confirmed", "needs_verification": False, "status": "open"},
        {"cwe": "CWE-200", "verification_level": "confirmed", "needs_verification": False, "status": "open"},
    ]
    m = compute_program_metrics(records)
    assert m["by_verification"] == {"confirmed": 1, "judge_confirmed": 1, "heuristic": 0, "inferred": 0}
    assert m["validated"] == 2
    # CWE-89 reaches impact, CWE-200 (info) does not
    assert m["validated_exploitable"] == 1


def test_needs_verification_excludes_from_validated():
    records = [
        {"cwe": "CWE-89", "verification_level": "confirmed", "needs_verification": True, "status": "open"},
        {"cwe": "CWE-89", "verification_level": "heuristic", "needs_verification": True, "status": "open"},
        {"cwe": "CWE-89", "verification_level": "inferred", "needs_verification": True, "status": "open"},
    ]
    m = compute_program_metrics(records)
    assert m["validated"] == 0  # all flagged for review
    assert m["validated_exploitable"] == 0
    assert m["needs_verification"] == 3


def test_fix_verification_rate_and_funnel_monotone():
    records = [
        {"cwe": "CWE-89", "verification_level": "confirmed", "status": "remediated"},
        {"cwe": "CWE-89", "verification_level": "confirmed", "status": "remediated"},
        {"cwe": "CWE-1004", "verification_level": "confirmed", "status": "open"},  # validated, not exploitable
        {"cwe": "CWE-89", "verification_level": "heuristic", "status": "open"},  # not validated
    ]
    m = compute_program_metrics(records)
    # 2 remediated / (open=2 + remediated=2) = 0.5
    assert m["fix_verification_rate"] == 0.5
    # funnel: candidatos=4, validados=3, explotables=2 (the two sqli), mitigados=2
    counts = [s["count"] for s in m["funnel"]]
    assert counts == [4, 3, 2, 2]
    # discovery→validated→exploitable is strictly narrowing
    assert counts[0] >= counts[1] >= counts[2]
    assert [s["stage"] for s in m["funnel"]][:3] == ["Candidatos", "Validados", "Explotables (path a impacto)"]


def test_route_registered_before_finding_id():
    """/findings/metrics must precede /findings/{finding_id} or 'metrics' is
    captured as an id."""
    from kryon.server.routes import findings as fmod

    paths = [getattr(r, "path", "") for r in fmod.router.routes]
    assert paths.index("/findings/metrics") < paths.index("/findings/{finding_id}")
