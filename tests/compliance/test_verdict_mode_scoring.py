"""verdict_mode='manual' controls must NOT be auto-scored as PASS.

The legacy map_findings_to_framework dispatcher initialized every control to
'pass' and never moved manual (governance/process) controls off it, inflating
compliance_percentage to a false 100% — contradicting each module's own
'never claim compliant' contract and CLAUDE.md policy.
"""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework


def test_hipaa_manual_controls_not_scored_pass_with_zero_findings():
    report = map_findings_to_framework([], "hipaa")
    # Some HIPAA controls are governance (verdict_mode="manual") — must be counted
    # as manual, NOT as passed.
    assert report.controls_manual > 0, "expected some manual governance controls"
    # Manual controls excluded from passed.
    assert report.controls_passed == report.controls_assessed - report.controls_manual - report.controls_failed
    # The report must NOT claim these governance controls PASSED.
    manual_evidence = [e for e in report.evidence if e.status == "manual"]
    assert len(manual_evidence) == report.controls_manual
    assert all(e.status != "pass" for e in manual_evidence)


def test_compliance_percentage_excludes_manual_from_denominator():
    report = map_findings_to_framework([], "hipaa")
    # % is over AUTO-scored controls only, not the full catalog.
    scored = report.controls_assessed - report.controls_manual
    if scored > 0:
        assert report.compliance_percentage == round((report.controls_passed / scored) * 100, 1)
    # And with zero findings, the auto (technical) controls pass, but the overall
    # picture is NOT "100% HIPAA compliant" — manual controls are visibly unassessed.
    assert report.controls_manual > 0
