"""Structural tests for CIS Windows Server 2022 L1 framework (F36)."""

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

_YAML = Path(__file__).resolve().parents[2] / "src/kryon/compliance/cis/frameworks/cis-windows-server-2022-l1.yaml"
_ID_RE = re.compile(r"^CIS-WIN-\d+(\.\d+){1,3}$")


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML)


def test_loads(framework):
    assert framework.metadata.id == "cis-windows-server-2022-l1"


def test_min_checks(framework):
    assert len(framework) >= 60, f"only {len(framework)}"


def test_ids_follow_format(framework):
    for c in framework.checks:
        assert _ID_RE.match(c.id), c.id


def test_expected_sections_present(framework):
    sections = {c.section.split(".", 1)[0] for c in framework.checks}
    # CIS Windows Server v3.0 L1 must cover at least: Account Policies (1),
    # Local Policies (2), Advanced Audit (17), Admin Templates Computer (18)
    assert {"1", "2", "17", "18"} <= sections, f"missing CIS sections: {sections}"


def test_natural_sort(framework):
    from kryon.compliance.runner import _natural_sort_key

    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key)


def _blob(c) -> str:
    return " ".join((getattr(c, f) or "").lower() for f in ("title", "rationale", "remediation", "command"))


def test_critical_controls_present(framework):
    critical = [c for c in framework.checks if c.severity == "CRITICAL"]
    assert len(critical) >= 5, f"only {len(critical)} CRITICAL controls"


def test_windows_native_commands(framework):
    """Must use reg/sc/net/auditpol/powershell, NOT bash or chmod."""
    win_tokens = (
        "reg query",
        "sc query",
        "sc qc",
        "net accounts",
        "net user",
        "auditpol",
        "powershell",
        "manage-bde",
        "wmic",
        "secedit",
    )
    win_cmds = [c for c in framework.checks if any(t in c.command for t in win_tokens)]
    assert len(win_cmds) >= 50, f"only {len(win_cmds)} Windows-native commands"


def test_critical_smbv1_coverage(framework):
    """SMBv1 must appear as CRITICAL — Wannacry-class exposure."""
    smb1 = [c for c in framework.checks if "smbv1" in c.title.lower() or "smb v1" in c.title.lower()]
    assert smb1, "no SMBv1 check found"
    assert any(c.severity == "CRITICAL" for c in smb1), "SMBv1 must include a CRITICAL check"


def test_critical_spooler_coverage(framework):
    """PrintNightmare — Spooler disable must be CRITICAL."""
    spooler = [c for c in framework.checks if "spooler" in c.title.lower()]
    assert spooler, "no Print Spooler check"
    assert any(c.severity == "CRITICAL" for c in spooler), "Spooler must be CRITICAL"


def test_llmnr_and_netbios_covered(framework):
    """LLMNR + NetBIOS poisoning countermeasures must be present."""
    blob = " ".join(_blob(c) for c in framework.checks)
    assert "llmnr" in blob, "LLMNR control missing"
    assert "netbios" in blob, "NetBIOS control missing"


def test_defender_and_credential_guard(framework):
    blob = " ".join(_blob(c) for c in framework.checks)
    for kw in ("defender", "credential guard", "scriptblock", "attack surface"):
        assert kw in blob, f"missing {kw!r} coverage"


def test_audit_policy_covered(framework):
    blob = " ".join(_blob(c) for c in framework.checks if c.section.startswith("17"))
    for kw in ("credential validation", "process creation", "audit policy change"):
        assert kw in blob, f"section 17 missing {kw!r}"
