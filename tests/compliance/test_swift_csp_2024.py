"""Structural tests for the SWIFT CSP v2024 framework (F40)."""

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
    / "swift-csp-2024.yaml"
)
_SWIFT_ID_RE = re.compile(r"^SWIFT-\d+\.\d+$")
_MIN_CHECKS = 15


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML_PATH)


def test_yaml_loads(framework):
    assert framework.metadata.id == "swift-csp-2024"
    assert "SWIFT" in framework.metadata.title


def test_minimum_check_count(framework):
    assert len(framework) >= _MIN_CHECKS


def test_all_ids_follow_swift_format(framework):
    for c in framework.checks:
        assert _SWIFT_ID_RE.match(c.id), f"malformed SWIFT id: {c.id!r}"


def test_natural_sort_order(framework):
    from kryon.compliance.runner import _natural_sort_key
    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key)


def test_principles_covered(framework):
    """CSCF 2024 principles we target: 1, 2, 4, 5, 6, 7."""
    principles = {c.section.split(".", 1)[0] for c in framework.checks}
    expected = {"1", "2", "4", "5", "6", "7"}
    missing = expected - principles
    assert not missing, f"missing CSCF principles: {missing}"


def test_critical_controls(framework):
    by_id = {c.id: c for c in framework.checks}
    # CSCF 1.1 secure zone firewall, 1.2 no internet exposure,
    # 4.2 MFA operators, 5.2 key-based SSH
    critical = {"SWIFT-1.1", "SWIFT-1.2", "SWIFT-4.2", "SWIFT-5.2"}
    for cid in critical:
        assert by_id[cid].severity == "CRITICAL", f"{cid} must be CRITICAL"


def test_every_check_has_substantive_fields(framework):
    for c in framework.checks:
        assert c.title.strip()
        assert len(c.command.strip()) >= 3
        assert len(c.remediation.strip()) >= 10
        assert c.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
