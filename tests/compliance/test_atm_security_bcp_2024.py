"""Structural tests for ATM Security BCP Paraguay 2024 framework (F43)."""

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
    / "src/kryon/compliance/cis/frameworks/atm-security-bcp-2024.yaml"
)
_ID_RE = re.compile(r"^ATM-\d+(\.\d+){1,2}$")


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML)


def test_loads(framework):
    assert framework.metadata.id == "atm-security-bcp-2024"


def test_min_checks(framework):
    assert len(framework) >= 20, f"only {len(framework)}"


def test_ids_follow_format(framework):
    for c in framework.checks:
        assert _ID_RE.match(c.id), c.id


def test_four_sections_covered(framework):
    sections = {c.section.split(".", 1)[0] for c in framework.checks}
    assert {"1", "2", "3", "4"} == sections


def _blob(c) -> str:
    return " ".join(
        (getattr(c, f) or "").lower()
        for f in ("title", "rationale", "remediation", "command")
    )


def test_physical_section_covers_antiskim_and_pts(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("1"))
    for kw in ("pci pts", "skimming", "camera", "privacy"):
        assert kw in blob, f"section 1 missing {kw!r}"


def test_os_section_covers_ndc_ddc_and_wdac(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("2"))
    for kw in ("ndc", "ddc", "wdac", "bitlocker", "xfs"):
        assert kw in blob, f"section 2 missing {kw!r}"


def test_crypto_section_covers_tr31_and_mtls(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("3"))
    for kw in ("tr-31", "mtls", "tls 1.2"):
        assert kw in blob, f"section 3 missing {kw!r}"


def test_ops_section_covers_pin_retry_and_ej(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("4"))
    for kw in ("pin", "retention", "ej", "reconcil", "pan"):
        assert kw in blob, f"section 4 missing {kw!r}"


def test_critical_controls_present(framework):
    """At least 3 CRITICAL (PCI PTS cert, FDI anti-skim, TR-31 wrapping)."""
    critical = [c for c in framework.checks if c.severity == "CRITICAL"]
    assert len(critical) >= 3, f"only {len(critical)} CRITICAL"


def test_bcp_2024_reference_present(framework):
    """BCP Paraguay 2024 disposition must be explicitly cited in rationale text."""
    citations = [c for c in framework.checks if "bcp" in (c.rationale or "").lower() and "2024" in (c.rationale or "")]
    assert len(citations) >= 3, f"only {len(citations)} checks cite BCP 2024"


def test_windows_specific_commands(framework):
    """ATM hosts are Windows — commands must use reg/wmic/powershell, not bash."""
    win_cmds = [
        c for c in framework.checks
        if any(t in c.command for t in ("reg query", "wmic", "powershell", "sc query", "sc config", "ipconfig", "manage-bde", "w32tm"))
    ]
    assert len(win_cmds) >= 15, f"only {len(win_cmds)} Windows-native commands"
