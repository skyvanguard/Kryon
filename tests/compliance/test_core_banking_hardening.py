"""Structural tests for Core Banking Hardening framework (F42).

T24 / Finacle / Flexcube OS+DB hardening. No public CIS benchmark covers
these vendor products, so this YAML is Kryon-internal (built from vendor
admin guides + BCP PY Res. 12/2021).
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
    pytest.skip("compliance/cis not importable", allow_module_level=True)

_YAML = (
    Path(__file__).resolve().parents[2]
    / "src/kryon/compliance/cis/frameworks/core-banking-hardening.yaml"
)
_ID_RE = re.compile(r"^CBH-\d+(\.\d+){1,2}$")


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML)


def test_loads(framework):
    assert framework.metadata.id == "core-banking-hardening"


def test_min_checks(framework):
    assert len(framework) >= 30, f"only {len(framework)}"


def test_ids_follow_format(framework):
    for c in framework.checks:
        assert _ID_RE.match(c.id), c.id


def test_six_sections_covered(framework):
    sections = {c.section.split(".", 1)[0] for c in framework.checks}
    assert {"1", "2", "3", "4", "5", "6"} == sections


def test_each_section_has_checks(framework):
    counts: dict[str, int] = {}
    for c in framework.checks:
        s = c.section.split(".", 1)[0]
        counts[s] = counts.get(s, 0) + 1
    for s in ("1", "2", "3", "4", "5", "6"):
        assert counts.get(s, 0) >= 3, f"section {s} has only {counts.get(s, 0)} checks"


def _blob(c) -> str:
    return " ".join(
        (getattr(c, f) or "").lower()
        for f in ("title", "rationale", "remediation", "command")
    )


def test_t24_checks_present(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("2"))
    for kw in ("tmsprod", "tafj", "tcs", "sms.user"):
        assert kw in blob, f"T24 section missing keyword {kw!r}"


def test_finacle_checks_present(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("3"))
    for kw in ("fcodba", "finacle", "weblogic"):
        assert kw in blob, f"Finacle section missing keyword {kw!r}"


def test_flexcube_checks_present(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("4"))
    for kw in ("fcubs", "fchome", "elcm", "sms"):
        assert kw in blob, f"Flexcube section missing keyword {kw!r}"


def test_database_section_covers_oracle_and_db2(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("5"))
    for kw in ("oracle", "db2", "listener.ora", "audit_trail"):
        assert kw in blob, f"DB section missing {kw!r}"


def test_audit_section_references_bcp(framework):
    """Section 6 must explicitly reference BCP Paraguay Res. 12/2021."""
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("6"))
    assert "bcp" in blob and "12/2021" in blob, "section 6 should reference BCP Res. 12/2021"


def test_critical_count(framework):
    critical = [c for c in framework.checks if c.severity == "CRITICAL"]
    assert len(critical) >= 5, f"expected >=5 CRITICAL, got {len(critical)}"
