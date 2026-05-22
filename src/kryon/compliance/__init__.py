"""Compliance framework mapping for security findings."""

from __future__ import annotations

from kryon.compliance.models import ComplianceReport, ControlEvidence
from kryon.compliance.pci_dss import map_finding_to_pci_controls
from kryon.compliance.soc2 import map_finding_to_soc2_controls
from kryon.intelligence.models import Finding

# Registry of all supported frameworks
_FRAMEWORK_MAP: dict[str, str] = {
    "pci_dss": "kryon.compliance.pci_dss",
    "soc2": "kryon.compliance.soc2",
    "nist_csf": "kryon.compliance.nist_csf",
    "iso_27001": "kryon.compliance.iso_27001",
    "dora": "kryon.compliance.dora",
    "nis2": "kryon.compliance.nis2",
    "cis_controls": "kryon.compliance.cis_controls",
    "cmmc": "kryon.compliance.cmmc",
    "zero_trust": "kryon.compliance.zero_trust",
}

# F203.P — infra-specific frameworks (fortigate, proxmox, unifi, active_directory)
# usan arquitectura distinta: self-registering checks via
# compliance/checks/<framework>/. Accesibles via run_compliance_audit(framework=...)
# NO via map_findings_to_framework. Listado explícito para discovery/docs.
_INFRA_FRAMEWORKS: tuple[str, ...] = (
    "fortigate", "proxmox", "unifi", "active_directory",
    "asterisk", "windows", "tomcat",
)


def map_findings_to_framework(findings: list[Finding], framework: str) -> ComplianceReport:
    """Map findings to a compliance framework and generate a report."""
    if framework == "pci_dss":
        return _build_pci_report(findings)
    elif framework == "soc2":
        return _build_soc2_report(findings)
    elif framework in _FRAMEWORK_MAP:
        return _build_generic_report(findings, framework)
    else:
        raise ValueError(f"Unknown compliance framework: {framework}. Available: {', '.join(_FRAMEWORK_MAP.keys())}")


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


def _build_generic_report(findings: list[Finding], framework: str) -> ComplianceReport:
    """Build a compliance report using dynamic framework import."""
    import importlib

    module_path = _FRAMEWORK_MAP[framework]
    mod = importlib.import_module(module_path)

    # Convention: each module has *_CONTROLS list and map_finding_to_*_controls function
    controls_list = None
    mapper_fn = None
    framework_display = framework.upper().replace("_", " ")

    for attr_name in dir(mod):
        attr = getattr(mod, attr_name)
        if attr_name.endswith("_CONTROLS") and isinstance(attr, list) and attr_name.isupper():
            controls_list = attr
        if attr_name.startswith("map_finding_to_") and callable(attr):
            mapper_fn = attr
        # Special: pick up display name
        if attr_name == "FRAMEWORK_NAME" and isinstance(attr, str):
            framework_display = attr

    if controls_list is None or mapper_fn is None:
        raise ValueError(f"Framework module {module_path} missing controls list or mapper function")

    evidence_map: dict[str, ControlEvidence] = {}
    for control in controls_list:
        evidence_map[control.id] = ControlEvidence(control_id=control.id, status="pass")

    for finding in findings:
        matched = mapper_fn(finding)
        for ctrl_id in matched:
            if ctrl_id in evidence_map:
                ev = evidence_map[ctrl_id]
                ev.findings.append(finding)
                ev.status = "fail"

    controls_assessed = len(evidence_map)
    controls_failed = sum(1 for e in evidence_map.values() if e.status == "fail")

    return ComplianceReport(
        framework=framework_display,
        controls_assessed=controls_assessed,
        controls_passed=controls_assessed - controls_failed,
        controls_failed=controls_failed,
        evidence=list(evidence_map.values()),
    )
