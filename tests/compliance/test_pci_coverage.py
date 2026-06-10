"""Tests for honest PCI-DSS AUTO vs MANUAL coverage classification."""

from __future__ import annotations

from types import SimpleNamespace

from kryon.compliance.pci_dss import (
    PCI_AUTO_CONTROLS,
    PCI_DSS_V4_CONTROLS,
    map_finding_to_pci_controls,
    pci_assessment_type,
    pci_coverage_summary,
)


def test_auto_controls_are_subset_of_catalog():
    catalog_ids = {c.id for c in PCI_DSS_V4_CONTROLS}
    assert PCI_AUTO_CONTROLS <= catalog_ids


def test_assessment_type_classifies():
    assert pci_assessment_type("2.2.2") == "AUTO"  # default-credential check exists
    assert pci_assessment_type("11.4.1") == "MANUAL"  # pen-test = documentary
    assert pci_assessment_type("12.3.1") == "MANUAL"  # risk assessment = documentary


def test_policy_controls_are_manual():
    """Inherently documentary/process controls must never be AUTO."""
    for documentary in ("1.1.6", "7.2.1", "7.2.2", "10.4.1", "11.3.1", "11.4.1", "12.3.1"):
        assert pci_assessment_type(documentary) == "MANUAL"


def test_coverage_summary_is_consistent():
    s = pci_coverage_summary()
    assert s["total"] == len(PCI_DSS_V4_CONTROLS)
    assert s["auto"] + s["manual"] == s["total"]
    assert s["auto"] == len(PCI_AUTO_CONTROLS)
    assert 0 <= s["auto_pct"] <= 100


def test_verdict_mode_applied_to_catalog():
    by_id = {c.id: c for c in PCI_DSS_V4_CONTROLS}
    assert by_id["2.2.2"].verdict_mode == "auto"
    assert by_id["11.4.1"].verdict_mode == "manual"


def test_exposed_service_maps_to_network_control():
    finding = SimpleNamespace(title="Redis exposed on 6379", description="open database")
    assert "1.2.1" in map_finding_to_pci_controls(finding)
