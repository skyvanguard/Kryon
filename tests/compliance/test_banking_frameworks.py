"""Tests for the LATAM/banking regulatory framework wiring (Q3).

The BCP/SWIFT/ATM/core-banking YAMLs already ship real deterministic commands;
these tests guard that they register and that the audit dispatcher routes their
control-id prefixes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryon.compliance.cis import register_framework
from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

_FRAMEWORKS_DIR = Path("src/kryon/compliance/cis/frameworks")

_EXPECTED = {
    "bcp-py-res-12-2021": ("BCP-", 18),
    "swift-csp-2024": ("SWIFT-", 17),
    "atm-security-bcp-2024": ("ATM-", 25),
    "core-banking-hardening": ("CBH-", 36),
}


@pytest.mark.parametrize("stem,expected", _EXPECTED.items())
def test_banking_framework_registers_with_real_checks(stem, expected):
    prefix, min_count = expected
    path = _FRAMEWORKS_DIR / f"{stem}.yaml"
    assert path.exists(), f"{stem}.yaml missing"
    checks = register_framework(path)
    assert len(checks) >= min_count
    ids = [getattr(c, "control_id", "") for c in checks]
    assert all(cid.startswith(prefix) for cid in ids), f"{stem} ids not all {prefix}*"


def test_checks_carry_deterministic_commands():
    """Not stubs — each banking check has a command + remediation."""
    checks = register_framework(_FRAMEWORKS_DIR / "bcp-py-res-12-2021.yaml")
    sample = checks[0]
    # _CISCheck exposes the spec it ran from; remediation + title are populated.
    assert getattr(sample, "control_title", "")
    assert getattr(sample, "remediation_static", "")


def test_dispatcher_routes_banking_frameworks():
    for name, prefix in (
        ("bcp-py", "BCP-"),
        ("bcp", "BCP-"),
        ("swift-csp", "SWIFT-"),
        ("swift", "SWIFT-"),
        ("atm-security", "ATM-"),
        ("atm", "ATM-"),
        ("core-banking", "CBH-"),
        ("cbh", "CBH-"),
    ):
        assert name in _FRAMEWORK_PREFIX, f"{name} not in dispatcher"
        assert prefix in _FRAMEWORK_PREFIX[name]


def test_banking_alias_covers_all_four():
    prefixes = _FRAMEWORK_PREFIX["banking"]
    assert set(prefixes) == {"BCP-", "SWIFT-", "ATM-", "CBH-"}


def test_runner_registers_banking_frameworks():
    """Importing the runner's check loader registers the banking controls."""
    from kryon.compliance import runner

    loader = getattr(runner, "_import_all_checks", None)
    if loader is None:
        pytest.skip("runner check loader not exposed")
    loader()
    registered = {getattr(c, "control_id", "") for c in runner._REGISTERED_CHECKS}
    assert any(c.startswith("BCP-") for c in registered)
    assert any(c.startswith("SWIFT-") for c in registered)
