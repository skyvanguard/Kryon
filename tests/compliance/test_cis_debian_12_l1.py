"""Structural tests for CIS Debian 12 L1 Server framework (F35)."""

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
    / "src/kryon/compliance/cis/frameworks/cis-debian-12-l1.yaml"
)
_CIS_ID_RE = re.compile(r"^CIS-DEB-\d+(\.\d+){1,3}$")


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML)


def test_loads(framework):
    assert framework.metadata.id == "cis-debian-12-l1"


def test_min_checks(framework):
    assert len(framework) >= 40, f"only {len(framework)}"


def test_ids_follow_format(framework):
    for c in framework.checks:
        assert _CIS_ID_RE.match(c.id), c.id


def test_sections_covered(framework):
    sections = {c.section.split(".", 1)[0] for c in framework.checks}
    assert {"1", "2", "3", "4", "5", "6"} <= sections


def test_severity_distribution(framework):
    counts: dict[str, int] = {}
    for c in framework.checks:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    assert counts.get("CRITICAL", 0) >= 2
    assert counts.get("HIGH", 0) >= 3


def test_natural_sort(framework):
    from kryon.compliance.runner import _natural_sort_key
    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key)
