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
    "hipaa": "kryon.compliance.hipaa",
    "gdpr": "kryon.compliance.gdpr",
    "psd2": "kryon.compliance.psd2",
    "fapi": "kryon.compliance.psd2",  # FAPI 1.0 Advanced is the RTS Art.30 technical profile
}

# F203.P — infra-specific frameworks (fortigate, proxmox, unifi, active_directory)
# usan arquitectura distinta: self-registering checks via
# compliance/checks/<framework>/. Accesibles via run_compliance_audit(framework=...)
# NO via map_findings_to_framework. Listado explícito para discovery/docs.
_INFRA_FRAMEWORKS: tuple[str, ...] = (
    "fortigate",
    "proxmox",
    "unifi",
    "active_directory",
    "asterisk",
    "windows",
    "tomcat",
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

    return _assemble_report(PCI_DSS_V4_CONTROLS, map_finding_to_pci_controls, findings, "PCI-DSS v4.0")


def _build_soc2_report(findings: list[Finding]) -> ComplianceReport:
    from kryon.compliance.soc2 import SOC2_TSC_CONTROLS

    return _assemble_report(SOC2_TSC_CONTROLS, map_finding_to_soc2_controls, findings, "SOC 2 Type II")


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

    return _assemble_report(controls_list, mapper_fn, findings, framework_display)


def _assemble_report(controls_list, mapper_fn, findings: list[Finding], framework_display: str) -> ComplianceReport:
    """Score a control catalog against findings, honoring verdict_mode.

    verdict_mode="manual" controls (governance/process a scanner can't verify)
    get status="manual" and are EXCLUDED from the auto pass/fail counts — they
    were previously initialized to "pass" and, since the keyword mappers never
    target them, stayed "pass" forever, inflating compliance_percentage to a
    false 100% (contradicting the modules' own 'never claim compliant' contract).
    """
    # verdict_mode defaults to "manual", so a framework that DOESN'T use the field
    # (e.g. SOC2, PCI-legacy) has every control at "manual" — we must not treat
    # those as unscored. A framework only "uses" verdict_mode if it explicitly
    # marks at least one control "auto" (HIPAA/GDPR/PSD2 do: auto technical +
    # manual governance). Otherwise fall back to the legacy all-auto behavior.
    uses_verdict_mode = any(getattr(c, "verdict_mode", "manual") == "auto" for c in controls_list)

    evidence_map: dict[str, ControlEvidence] = {}
    manual_ids: set[str] = set()
    for control in controls_list:
        is_manual = uses_verdict_mode and getattr(control, "verdict_mode", "manual") == "manual"
        if is_manual:
            evidence_map[control.id] = ControlEvidence(control_id=control.id, status="manual")
            manual_ids.add(control.id)
        else:
            evidence_map[control.id] = ControlEvidence(control_id=control.id, status="pass")

    for finding in findings:
        matched = mapper_fn(finding)
        for ctrl_id in matched:
            if ctrl_id in evidence_map and ctrl_id not in manual_ids:
                ev = evidence_map[ctrl_id]
                ev.findings.append(finding)
                ev.status = "fail"

    controls_assessed = len(evidence_map)
    controls_manual = len(manual_ids)
    controls_failed = sum(1 for e in evidence_map.values() if e.status == "fail")

    return ComplianceReport(
        framework=framework_display,
        controls_assessed=controls_assessed,
        controls_passed=controls_assessed - controls_manual - controls_failed,
        controls_failed=controls_failed,
        controls_manual=controls_manual,
        evidence=list(evidence_map.values()),
    )
