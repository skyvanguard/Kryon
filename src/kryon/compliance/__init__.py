"""Compliance framework mapping for security findings."""

from __future__ import annotations

from kryon.compliance.models import ComplianceReport, ControlEvidence
from kryon.compliance.pci_dss import map_finding_to_pci_controls
from kryon.compliance.soc2 import map_finding_to_soc2_controls
from kryon.intelligence.models import Finding


def map_findings_to_framework(findings: list[Finding], framework: str) -> ComplianceReport:
    """Map findings to a compliance framework and generate a report."""
    if framework == "pci_dss":
        return _build_pci_report(findings)
    elif framework == "soc2":
        return _build_soc2_report(findings)
    else:
        raise ValueError(f"Unknown compliance framework: {framework}")


def _build_pci_report(findings: list[Finding]) -> ComplianceReport:
    from kryon.compliance.pci_dss import PCI_DSS_V4_CONTROLS

    evidence_map: dict[str, ControlEvidence] = {}
    for control in PCI_DSS_V4_CONTROLS:
        evidence_map[control.id] = ControlEvidence(control_id=control.id, status="pass")

    for finding in findings:
        matched = map_finding_to_pci_controls(finding)
        for ctrl_id in matched:
            if ctrl_id in evidence_map:
                ev = evidence_map[ctrl_id]
                ev.findings.append(finding)
                ev.status = "fail"

    controls_assessed = len(evidence_map)
    controls_failed = sum(1 for e in evidence_map.values() if e.status == "fail")

    return ComplianceReport(
        framework="PCI-DSS v4.0",
        controls_assessed=controls_assessed,
        controls_passed=controls_assessed - controls_failed,
        controls_failed=controls_failed,
        evidence=list(evidence_map.values()),
    )


def _build_soc2_report(findings: list[Finding]) -> ComplianceReport:
    from kryon.compliance.soc2 import SOC2_TSC_CONTROLS

    evidence_map: dict[str, ControlEvidence] = {}
    for control in SOC2_TSC_CONTROLS:
        evidence_map[control.id] = ControlEvidence(control_id=control.id, status="pass")

    for finding in findings:
        matched = map_finding_to_soc2_controls(finding)
        for ctrl_id in matched:
            if ctrl_id in evidence_map:
                ev = evidence_map[ctrl_id]
                ev.findings.append(finding)
                ev.status = "fail"

    controls_assessed = len(evidence_map)
    controls_failed = sum(1 for e in evidence_map.values() if e.status == "fail")

    return ComplianceReport(
        framework="SOC 2 Type II",
        controls_assessed=controls_assessed,
        controls_passed=controls_assessed - controls_failed,
        controls_failed=controls_failed,
        evidence=list(evidence_map.values()),
    )
