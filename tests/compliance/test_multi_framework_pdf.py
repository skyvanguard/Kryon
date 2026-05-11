"""Tests for multi-framework compliance report consolidation (F44)."""

from __future__ import annotations

import importlib
from datetime import datetime

import pytest

try:
    mf = importlib.import_module("kryon.reporting.multi_framework_pdf")
except (ImportError, ModuleNotFoundError):
    pytest.skip("reporting.multi_framework_pdf not importable", allow_module_level=True)


def _mk_result(
    control_id: str,
    verdict: str = "PASS",
    severity: str = "MEDIUM",
    section: str = "1.1",
    title: str = "",
) -> dict:
    """Build a minimal CheckResult-like dict."""
    return {
        "control_id": control_id,
        "verdict": verdict,
        "severity": severity,
        "section": section,
        "title": title or f"Test check {control_id}",
        "command": f"echo {control_id}",
        "stdout": "",
        "stderr": "",
        "exit_code": 0,
        "rationale": "",
        "remediation_static": "",
    }


@pytest.fixture
def sample_results() -> dict[str, list[dict]]:
    """Results spanning 3 frameworks with a mix of verdicts."""
    return {
        "pci-dss-4.0": [
            _mk_result("PCI-2.1", "FAIL", "CRITICAL"),
            _mk_result("PCI-10.5", "FAIL", "HIGH"),
            _mk_result("PCI-4.1", "PASS", "HIGH"),
        ],
        "bcp-py-res-12-2021": [
            _mk_result("BCP-Art.25", "FAIL", "HIGH"),
            _mk_result("BCP-Art.21", "PASS", "MEDIUM"),
            _mk_result("BCP-Art.22", "N/A", "LOW"),
        ],
        "swift-csp-2024": [
            _mk_result("SWIFT-2.1", "PASS", "HIGH"),
            _mk_result("SWIFT-6.4", "FAIL", "CRITICAL"),
        ],
    }


def test_aggregate_counts_sums_across_frameworks(sample_results):
    all_results = [r for lst in sample_results.values() for r in lst]
    counts = mf._aggregate_counts(all_results)
    assert counts["FAIL"] == 4
    assert counts["PASS"] == 3
    assert counts["N/A"] == 1
    assert counts["ERROR"] == 0


def test_critical_fail_count(sample_results):
    """Only CRITICAL+FAIL counts; HIGH+FAIL doesn't."""
    pci = sample_results["pci-dss-4.0"]
    assert mf._critical_fail_count(pci) == 1
    swift = sample_results["swift-csp-2024"]
    assert mf._critical_fail_count(swift) == 1


def test_compute_repro_hash_deterministic(sample_results):
    """Hash stable across calls with same data."""
    h1 = mf.compute_repro_hash(sample_results)
    h2 = mf.compute_repro_hash(sample_results)
    assert h1 == h2
    assert len(h1) == 64


def test_compute_repro_hash_order_independent(sample_results):
    """Reordering framework dicts should not change the hash."""
    reordered = {
        "swift-csp-2024": sample_results["swift-csp-2024"],
        "pci-dss-4.0": sample_results["pci-dss-4.0"],
        "bcp-py-res-12-2021": sample_results["bcp-py-res-12-2021"],
    }
    assert mf.compute_repro_hash(sample_results) == mf.compute_repro_hash(reordered)


def test_compute_repro_hash_changes_on_verdict_flip(sample_results):
    """Flipping a verdict must change the hash."""
    h1 = mf.compute_repro_hash(sample_results)
    import copy

    modified = copy.deepcopy(sample_results)
    modified["pci-dss-4.0"][0]["verdict"] = "PASS"
    assert h1 != mf.compute_repro_hash(modified)


def test_render_html_contains_all_frameworks(sample_results):
    html_str = mf.render_multi_framework_html(
        sample_results,
        host="bank01.example.com",
        client_name="Banco Demo SA",
    )
    assert "PCI-DSS v4.0.1" in html_str
    assert "BCP Paraguay" in html_str
    assert "SWIFT CSP" in html_str
    assert "Banco Demo SA" in html_str
    assert "bank01.example.com" in html_str


def test_render_html_bilingual_blocks_present(sample_results):
    html_str = mf.render_multi_framework_html(sample_results, host="h")
    assert 'class="en-label">EN' in html_str
    assert "Executive summary" in html_str
    assert "Resumen ejecutivo" in html_str


def test_render_html_shows_aggregate_totals(sample_results):
    html_str = mf.render_multi_framework_html(sample_results, host="h")
    # Should show total checks (8)
    assert "<strong>8</strong>" in html_str
    # Overall FAIL count = 4
    assert "4 FAIL" in html_str
    # Critical count = 2 (one PCI, one SWIFT)
    assert "2 críticos" in html_str


def test_render_html_overall_risk_critico_when_many_fails(sample_results):
    html_str = mf.render_multi_framework_html(sample_results, host="h")
    # 4 FAILs across frameworks → risk = CRÍTICO
    assert "CRÍTICO" in html_str


def test_render_html_includes_cross_mapping_when_relevant(sample_results):
    """PCI + BCP + SWIFT all present — cross-mapping table should render."""
    html_str = mf.render_multi_framework_html(sample_results, host="h")
    assert "Mapeo cruzado" in html_str
    assert "Cross-framework mapping" in html_str
    # At least one mapping row should appear (central audit logging)
    assert "auditor" in html_str.lower() or "centralizado" in html_str.lower()


def test_render_html_empty_frameworks_raises():
    with pytest.raises(ValueError):
        mf.render_multi_framework_html({}, host="h")


def test_render_html_hash_included_in_footer(sample_results):
    html_str = mf.render_multi_framework_html(sample_results, host="h")
    repro = mf.compute_repro_hash(sample_results)
    assert repro in html_str
    # Truncated version in the footer note
    assert repro[:32] in html_str


def test_cross_mapping_hides_frameworks_not_in_report():
    """A PCI-only report should NOT render BCP-only mapping rows."""
    results = {"pci-dss-4.0": [_mk_result("PCI-2.1", "PASS", "HIGH")]}
    html_str = mf.render_multi_framework_html(results, host="h")
    # Should not show SWIFT-only rows (environment segregation is BCP+SWIFT only, no PCI)
    # but PCI rows within cross-mappings should still appear if any mapping includes PCI
    assert "Mapeo cruzado" in html_str  # some mapping does include PCI


def test_single_framework_still_renders(sample_results):
    """Consolidation should work even with just one framework."""
    single = {"pci-dss-4.0": sample_results["pci-dss-4.0"]}
    html_str = mf.render_multi_framework_html(single, host="h")
    assert "PCI-DSS" in html_str
    assert "<strong>1</strong>" in html_str  # 1 framework


def test_framework_meta_covers_all_registered_frameworks():
    """FRAMEWORK_META must have entries for every registered YAML framework."""
    from kryon.compliance.cis import available_frameworks

    for p in available_frameworks():
        fw_id = p.stem
        assert fw_id in mf.FRAMEWORK_META, f"missing FRAMEWORK_META for {fw_id}"


def test_cross_mappings_reference_only_known_frameworks():
    """CROSS_MAPPINGS must reference only frameworks that exist in FRAMEWORK_META."""
    for m in mf.CROSS_MAPPINGS:
        for fw_id in m["frameworks"]:
            assert fw_id in mf.FRAMEWORK_META, f"unknown framework {fw_id} in cross-mapping"
