"""F210 Fase 4 — device-compliance findings carry a verification_level so
ERROR verdicts and banner/version-inferred controls are downgraded to
"requiere verificación" instead of ground truth."""

from __future__ import annotations

from kryon.cli.engage import _compliance_verification_level
from kryon.scoring.confidence import annotate_confidence, compute_confidence


def test_directly_probed_fail_is_confirmed():
    # A normal on-box config FAIL is ground truth.
    assert _compliance_verification_level("FAIL", "PVE-2.3") == "confirmed"
    assert _compliance_verification_level("FAIL", "FGT-1.1") == "confirmed"


def test_error_verdict_is_heuristic():
    # ERROR = the check couldn't determine the state → never ground truth.
    assert _compliance_verification_level("ERROR", "PVE-2.3") == "heuristic"
    assert _compliance_verification_level("ERROR", "FGT-1.1") == "heuristic"


def test_banner_inferred_controls_are_heuristic():
    # Tomcat EOL (HTTP banner) + FortiOS version→CVE mapping (backport-prone).
    assert _compliance_verification_level("FAIL", "TOMCAT-1.1") == "heuristic"
    assert _compliance_verification_level("FAIL", "FGT-5.3") == "heuristic"


def test_banner_inferred_match_is_case_insensitive():
    assert _compliance_verification_level("FAIL", "tomcat-1.1") == "heuristic"


def test_onbox_version_currency_stays_confirmed():
    # Reliable on-box version reads (pveversion / get system status) are
    # NOT downgraded — only remote-banner / version→CVE inference is.
    assert _compliance_verification_level("FAIL", "PVE-5.1") == "confirmed"
    assert _compliance_verification_level("FAIL", "FGT-5.1") == "confirmed"
    assert _compliance_verification_level("FAIL", "XEN-2.1") == "confirmed"


# ---------------------------------------------------------------------------
# Integration with confidence scoring — the downgrade actually flows through
# ---------------------------------------------------------------------------


def _finding(rule_id: str, level: str):
    from kryon.cli.engage import make_finding

    return make_finding(
        cwe="CWE-0",
        severity="HIGH",
        host="root@10.0.0.11",
        rule_id=rule_id,
        message="m",
        verification_level=level,
    )


def test_heuristic_compliance_finding_scored_needs_review():
    f = _finding("TOMCAT-1.1", "heuristic")
    ann = compute_confidence([f])[0]
    assert ann.confidence < 0.7
    assert ann.needs_verification is True


def test_confirmed_compliance_finding_stays_ground_truth():
    f = _finding("PVE-2.3", "confirmed")
    ann = compute_confidence([f])[0]
    # PVE- is a deterministic prefix → confirmed → 1.0.
    assert ann.confidence == 1.0
    assert ann.needs_verification is False


def test_annotate_flags_heuristic_finding_in_place():
    f = _finding("FGT-5.3", "heuristic")
    annotate_confidence([f])
    assert f.needs_verification is True
    assert f.confidence < 0.7
