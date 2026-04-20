"""Structural tests for the CIS Ubuntu 22.04 LTS Level 1 framework (F34).

These are YAML-shape tests — they do NOT execute the shell commands
(that requires a real Ubuntu 22.04 target under F45 regression harness).
What we verify here:

- YAML parses cleanly through the F33 importer
- Expected number of checks covering every CIS section
- All ids are unique, lexicographically sorted, and follow CIS-X.Y(.Z) format
- Every severity is valid
- Every check has a non-trivial command, remediation, and pass_when
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
    Path(__file__).resolve().parents[2]
    / "src"
    / "kryon"
    / "compliance"
    / "cis"
    / "frameworks"
    / "cis-ubuntu-22.04-l1.yaml"
)

_CIS_ID_RE = re.compile(r"^CIS-\d+(\.\d+){1,3}$")
_EXPECTED_SECTIONS = {"1", "2", "3", "4", "5", "6"}
_MIN_CHECKS = 60


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML_PATH)


def test_yaml_loads(framework):
    assert framework.metadata.id == "cis-ubuntu-22.04-l1"
    assert framework.metadata.version.startswith("0.")


def test_has_at_least_expected_check_count(framework):
    assert len(framework) >= _MIN_CHECKS, (
        f"Expected >= {_MIN_CHECKS} checks, found {len(framework)}"
    )


def test_all_ids_are_unique_and_well_formed(framework):
    ids = [c.id for c in framework.checks]
    assert len(ids) == len(set(ids)), "duplicate check ids"
    for cid in ids:
        assert _CIS_ID_RE.match(cid), f"malformed id: {cid!r}"


def test_ids_sorted_in_natural_order(framework):
    """CIS ids use natural (numeric) ordering so CIS-5.2.2 precedes
    CIS-5.2.10. The YAML must be authored in the same order the runner
    executes them, which is the natural-sort order."""
    from kryon.compliance.runner import _natural_sort_key

    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key), (
        "YAML should list checks in natural-order (not lexicographic)"
    )


def test_every_cis_section_is_represented(framework):
    first_digits = {c.section.split(".", 1)[0] for c in framework.checks}
    missing = _EXPECTED_SECTIONS - first_digits
    assert not missing, f"CIS sections not represented: {missing}"


def test_every_check_has_non_trivial_fields(framework):
    for c in framework.checks:
        assert c.title.strip(), f"{c.id}: empty title"
        assert len(c.command.strip()) >= 3, f"{c.id}: trivial command"
        assert len(c.remediation.strip()) >= 10, f"{c.id}: trivial remediation"
        assert c.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_every_check_has_valid_pass_when(framework):
    """Each pass_when should have been parsed successfully and carry
    at least one predicate or combinator."""
    for c in framework.checks:
        pw = c.pass_when
        has_any = any(
            getattr(pw, f) is not None
            for f in (
                "stdout_contains", "stdout_not_contains",
                "stdout_matches", "stdout_not_matches",
                "stdout_empty", "exit_code_is",
                "all_of", "any_of", "not_",
            )
        )
        assert has_any, f"{c.id}: empty pass_when parsed"


def test_severities_distribution_has_critical_and_high(framework):
    """Ensure we're not shipping a framework where everything is LOW."""
    counts: dict[str, int] = {}
    for c in framework.checks:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    assert counts.get("CRITICAL", 0) >= 2, f"expected >=2 CRITICAL, got {counts}"
    assert counts.get("HIGH", 0) >= 5, f"expected >=5 HIGH, got {counts}"


def test_register_all_frameworks_ingests_ubuntu_file():
    """The auto-discovery helper must pick up the production framework
    and skip the _sample.yaml file."""
    from kryon.compliance import cis as cis_pkg
    from kryon.compliance import runner

    before = {c.control_id for c in runner._REGISTERED_CHECKS}
    try:
        results = cis_pkg.register_all_frameworks(include_samples=False)
        assert "cis-ubuntu-22.04-l1" in results
        assert "_sample" not in results
        assert len(results["cis-ubuntu-22.04-l1"]) >= _MIN_CHECKS
    finally:
        runner._REGISTERED_CHECKS[:] = [
            c for c in runner._REGISTERED_CHECKS if c.control_id in before
        ]
