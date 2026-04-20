"""Structural tests for the BCP Paraguay Res. 12/2021 framework (F41)."""

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
    Path(__file__).resolve().parents[2]
    / "src"
    / "kryon"
    / "compliance"
    / "cis"
    / "frameworks"
    / "bcp-py-res-12-2021.yaml"
)
_BCP_ID_RE = re.compile(r"^BCP-\d+\.\d+$")
_MIN_CHECKS = 15


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML_PATH)


def test_yaml_loads(framework):
    assert framework.metadata.id == "bcp-py-res-12-2021"
    assert "Res. 12/2021" in framework.metadata.title


def test_minimum_check_count(framework):
    assert len(framework) >= _MIN_CHECKS, f"only {len(framework)} checks"


def test_all_ids_follow_bcp_format(framework):
    for c in framework.checks:
        assert _BCP_ID_RE.match(c.id), f"malformed BCP id: {c.id!r}"


def test_natural_sort_order(framework):
    from kryon.compliance.runner import _natural_sort_key
    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key)


def test_sections_represented(framework):
    """Confirm the framework spans the expected BCP sections."""
    sections = {c.section for c in framework.checks}
    # Roman numerals in YAML — we match a subset we know we covered
    expected_subset = {"VII", "XVIII", "XXI", "XXVI", "XXXIII"}
    assert expected_subset <= sections, f"missing sections: {expected_subset - sections}"


def test_critical_foundational_controls(framework):
    """Key banking-critical controls must be CRITICAL severity."""
    by_id = {c.id: c for c in framework.checks}
    # BCP-7.4 (SSH key auth), 26.1 (MFA admin), 26.4 (UID 0 uniqueness),
    # 33.1 (ATM firewall)
    critical = {"BCP-7.4", "BCP-26.1", "BCP-26.4", "BCP-33.1"}
    for cid in critical:
        assert by_id[cid].severity == "CRITICAL", f"{cid} should be CRITICAL"


def test_atm_section_covered(framework):
    """ATM (sección XXXIII) should have dedicated checks."""
    atm_ids = [c.id for c in framework.checks if c.id.startswith("BCP-33")]
    assert len(atm_ids) >= 3, f"only {len(atm_ids)} ATM checks, expected >=3"


def test_every_check_has_substantive_fields(framework):
    for c in framework.checks:
        assert c.title.strip()
        assert len(c.command.strip()) >= 3
        assert len(c.remediation.strip()) >= 10
        assert c.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
