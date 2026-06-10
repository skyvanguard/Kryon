"""Tests for the CIS Controls v8.1 deterministic crosswalk."""

from __future__ import annotations

from kryon.compliance.cis import cis_controls_crosswalk as xwalk
from kryon.compliance.cis.cis_controls_crosswalk import (
    CHECK_TO_SAFEGUARD,
    _aggregate,
    audit_cis_controls,
    map_results_to_safeguards,
    validate_crosswalk,
)


class _FakeResult:
    def __init__(self, control_id: str, verdict: str) -> None:
        self.control_id = control_id
        self.verdict = verdict


class TestCrosswalkIntegrity:
    def test_no_orphan_safeguard_ids(self):
        """Every crosswalk target must be a real v8.1 safeguard id."""
        assert validate_crosswalk() == []

    def test_check_ids_are_unique_keys(self):
        assert len(CHECK_TO_SAFEGUARD) == len(set(CHECK_TO_SAFEGUARD))


class TestAggregation:
    def test_fail_closed_any_fail_wins(self):
        assert _aggregate(["PASS", "FAIL", "PASS"]) == "FAIL"

    def test_error_beats_pass(self):
        assert _aggregate(["PASS", "ERROR"]) == "ERROR"

    def test_pass_with_na_is_pass(self):
        assert _aggregate(["PASS", "N/A"]) == "PASS"

    def test_empty_is_na(self):
        assert _aggregate([]) == "N/A"


class TestMapResultsToSafeguards:
    def test_returns_all_153(self):
        out = map_results_to_safeguards([])
        assert len(out) == 153
        # With no results, every safeguard is manual.
        assert all(s["verdict_mode"] == "manual" for s in out)
        assert all(s["verdict"] == "MANUAL" for s in out)

    def test_mapped_check_flips_to_auto(self):
        out = map_results_to_safeguards([_FakeResult("2.2.2", "FAIL")])
        cis_4_7 = next(s for s in out if s["id"] == "CIS-4.7")
        assert cis_4_7["verdict_mode"] == "auto"
        assert cis_4_7["verdict"] == "FAIL"
        assert {"check_id": "2.2.2", "verdict": "FAIL"} in cis_4_7["evidence_checks"]

    def test_multiple_checks_aggregate_fail_closed(self):
        # Both 2.2.2 and FGT-1.1 map to CIS-4.7; one FAIL → FAIL.
        out = map_results_to_safeguards([_FakeResult("2.2.2", "PASS"), _FakeResult("FGT-1.1", "FAIL")])
        cis_4_7 = next(s for s in out if s["id"] == "CIS-4.7")
        assert cis_4_7["verdict"] == "FAIL"
        assert len(cis_4_7["evidence_checks"]) == 2

    def test_governance_controls_stay_manual(self):
        """Controls 14/15/17/18 are governance — never auto even with checks run."""
        out = map_results_to_safeguards([_FakeResult("2.2.2", "FAIL")])
        for ctrl in ("14", "15", "17", "18"):
            sgs = [s for s in out if s["safeguard"].startswith(ctrl + ".")]
            assert sgs
            assert all(s["verdict_mode"] == "manual" for s in sgs)


class TestAuditCisControls:
    def test_audit_summary_shape(self, monkeypatch):
        fake = [
            _FakeResult("2.2.2", "FAIL"),
            _FakeResult("8.4.1", "PASS"),
            _FakeResult("3.5.1", "PASS"),
        ]
        monkeypatch.setattr(xwalk, "_import_all_checks", lambda: None, raising=False)
        # Patch the names imported inside audit_cis_controls.
        import kryon.compliance.runner as runner

        monkeypatch.setattr(runner, "run_all", lambda ctx, run_id=None: fake)
        monkeypatch.setattr(runner, "_import_all_checks", lambda: None)
        monkeypatch.setattr(runner, "reproducibility_hash", lambda r: "deadbeef")

        class Ctx:
            host = "10.0.0.9"

        report = audit_cis_controls(Ctx())
        assert report["framework"] == "CIS Controls v8.1"
        assert report["host"] == "10.0.0.9"
        assert report["repro_hash"] == "deadbeef"
        assert report["checks_run"] == 3
        s = report["summary"]
        assert s["total_safeguards"] == 153
        assert s["auto_covered"] >= 2
        assert s["manual_required"] == 153 - s["auto_covered"]
        assert s["auto_fail"] >= 1  # 2.2.2 FAIL → CIS-4.7


def test_f31_expansion_covers_at_least_43_safeguards():
    """F3.1 — the crosswalk derives >= 43 distinct AUTO safeguards (was 32)."""
    covered: set[str] = set()
    for sgs in CHECK_TO_SAFEGUARD.values():
        covered.update(sgs)
    assert len(covered) >= 43


def test_f31_new_safeguards_present():
    covered: set[str] = set()
    for sgs in CHECK_TO_SAFEGUARD.values():
        covered.update(sgs)
    for sg in ("4.9", "5.1", "6.3", "13.2", "10.6", "13.10", "12.5", "3.12", "3.3", "13.4", "13.7"):
        assert sg in covered, f"F3.1 safeguard {sg} not covered"


def test_f31_mappings_are_valid_safeguards():
    """No invented safeguard ids — every crosswalk target is a real v8.1 id."""
    assert validate_crosswalk() == []
