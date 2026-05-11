"""Structural tests for the PCI-DSS 4.0 framework (F39).

Like the CIS Ubuntu tests: YAML-shape validation, NOT execution. Real
execution lives in F45 regression harness.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

try:
    _importer = importlib.import_module("kryon.compliance.cis.importer")
    load_framework = _importer.load_framework
except (ImportError, ModuleNotFoundError):
    pytest.skip("compliance/cis module not importable", allow_module_level=True)


_YAML_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "kryon" / "compliance" / "cis" / "frameworks" / "pci-dss-4.0.yaml"
)

# PCI-DSS 4.0 ids: "1.4.3", "10.2.1.2", "8.3.1" — up to 4 numeric levels.
_PCI_ID_RE = re.compile(r"^\d+(\.\d+){1,3}$")
_EXPECTED_REQS = {"1", "2", "3", "8", "10", "11"}
_EXISTING_HAND_WRITTEN_IDS = {
    "2.2.2",
    "2.2.7",
    "6.3.3",
    "6.4.1",
    "8.3.6",
    "10.2.1",
}
_MIN_CHECKS = 25


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML_PATH)


def test_yaml_loads(framework):
    assert framework.metadata.id == "pci-dss-4.0"
    assert "4.0" in framework.metadata.title or "4.0" in framework.metadata.version


def test_has_minimum_check_count(framework):
    assert len(framework) >= _MIN_CHECKS, f"only {len(framework)} checks"


def test_ids_well_formed_and_unique(framework):
    ids = [c.id for c in framework.checks]
    assert len(ids) == len(set(ids)), "duplicate check ids"
    for cid in ids:
        assert _PCI_ID_RE.match(cid), f"malformed PCI id: {cid!r}"


def test_does_not_duplicate_hand_written_checks(framework):
    """The 6 controls implemented as Python modules (F15.1 baseline)
    must not also appear in the YAML — runner.register_check is
    idempotent by id so the first-registered wins, which would make
    the YAML version silently unreachable."""
    yaml_ids = {c.id for c in framework.checks}
    overlap = yaml_ids & _EXISTING_HAND_WRITTEN_IDS
    assert not overlap, f"YAML duplicates hand-written ids: {overlap}. Hand-written wins — YAML check becomes dead."


def test_ids_in_natural_order(framework):
    from kryon.compliance.runner import _natural_sort_key

    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key), "YAML should list PCI ids in natural (numeric) order"


def test_covers_all_expected_requirements(framework):
    reqs = {c.section for c in framework.checks}
    missing = _EXPECTED_REQS - reqs
    assert not missing, f"PCI requirements not represented: {missing}"


def test_critical_findings_on_foundational_controls(framework):
    """Req 1.3.1 (firewall active), 2.2.5 (insecure svc), 8.3.1
    (password auth), 8.4.1 (MFA) are CRITICAL by PCI gravity."""
    by_id = {c.id: c for c in framework.checks}
    assert by_id["1.3.1"].severity == "CRITICAL"
    assert by_id["2.2.5"].severity == "CRITICAL"
    assert by_id["8.3.1"].severity == "CRITICAL"
    assert by_id["8.4.1"].severity == "CRITICAL"


def test_every_check_has_substantive_fields(framework):
    for c in framework.checks:
        assert c.title.strip()
        assert len(c.command.strip()) >= 3
        assert len(c.remediation.strip()) >= 10
        assert c.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


# ---------- F39.2 — runner integration: 40 PCI checks live in registry ----------


def test_runner_registers_full_pci_baseline() -> None:
    """The CLAUDE.md banking pitch promises 40 PCI-DSS checks. This pins
    the actual count of PCI-shaped IDs the runner registers — YAML
    framework + hand-written sections, deduplicated."""
    import re

    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    pci_id_re = re.compile(r"^\d+(\.\d+){1,3}$")
    pci_checks = [c for c in registered_checks() if pci_id_re.match(c.control_id)]

    assert len(pci_checks) == 40, (
        f"PCI baseline drifted from 40 (CLAUDE.md commitment) to "
        f"{len(pci_checks)}. If this is intentional, update CLAUDE.md "
        f"and the Banking-vertical reality table."
    )

    # Sanity — no duplicate ids from YAML colliding with hand-written.
    ids = [c.control_id for c in pci_checks]
    assert len(ids) == len(set(ids)), f"duplicate PCI control_ids: {sorted(ids)}"


def test_runner_pci_baseline_covers_4_2_1_and_5_2_1_and_8_4_2() -> None:
    """The 3 controls added on top of the YAML 31 + Python 6 to reach 40
    must be present in the registry — these are the cryptography (4.2.1),
    anti-malware (5.2.1) and broad-MFA (8.4.2) controls explicitly
    called out by PCI auditors when the original YAML omitted them."""
    from kryon.compliance.runner import _import_all_checks, registered_checks

    _import_all_checks()
    by_id = {c.control_id: c for c in registered_checks()}
    for required in ("4.2.1", "5.2.1", "8.4.2"):
        assert required in by_id, f"PCI control {required} missing from registry — the 6→40 upgrade pipeline regressed."
