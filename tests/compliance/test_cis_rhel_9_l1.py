"""Structural tests for CIS RHEL 9 L1 Server framework (F35)."""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

try:
    _importer = importlib.import_module("kryon.compliance.cis.importer")
    load_framework = _importer.load_framework
except (ImportError, ModuleNotFoundError):
    pytest.skip("compliance/cis not importable", allow_module_level=True)

_YAML = (
    Path(__file__).resolve().parents[2]
    / "src/kryon/compliance/cis/frameworks/cis-rhel-9-l1.yaml"
)
_ID_RE = re.compile(r"^CIS-RHEL-\d+(\.\d+){1,3}$")


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML)


def test_loads(framework):
    assert framework.metadata.id == "cis-rhel-9-l1"


def test_min_checks(framework):
    assert len(framework) >= 40


def test_ids_follow_format(framework):
    for c in framework.checks:
        assert _ID_RE.match(c.id), c.id


def test_sections_covered(framework):
    sections = {c.section.split(".", 1)[0] for c in framework.checks}
    assert {"1", "2", "3", "4", "5", "6"} <= sections


def test_natural_sort(framework):
    from kryon.compliance.runner import _natural_sort_key
    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key)


def test_selinux_checks_present(framework):
    """RHEL 9 must have SELinux-specific controls (key delta vs Ubuntu/Debian)."""
    selinux_controls = [c for c in framework.checks if "selinux" in c.title.lower()]
    assert len(selinux_controls) >= 2


def test_firewalld_checks_present(framework):
    """RHEL 9 uses firewalld, not ufw."""
    fw_controls = [c for c in framework.checks if "firewalld" in c.title.lower()]
    assert len(fw_controls) >= 1


def test_dnf_based_package_checks(framework):
    """Package checks should use rpm/dnf commands, not dpkg/apt."""
    pkg_commands = [c.command for c in framework.checks if "rpm -q" in c.command or "dnf" in c.command]
    assert len(pkg_commands) >= 10, "expected >=10 RPM-based checks"
