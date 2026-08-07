"""Tests for the audit-bank-full skill playbook (F46).

Verifies the orchestrator skill is discoverable, has the required
metadata, references the right tools, and triggers on banking-audit
intents.
"""

from __future__ import annotations

import importlib

import pytest

try:
    _mod = importlib.import_module("kryon.skills.loader")
    SkillLoader = _mod.SkillLoader
except (ImportError, ModuleNotFoundError):
    pytest.skip("kryon.skills.loader not importable", allow_module_level=True)


@pytest.fixture(scope="module")
def loader():
    loader = SkillLoader()
    loader.scan()
    return loader


@pytest.fixture(scope="module")
def skill(loader):
    s = loader.get_by_name("audit-bank-full")
    if s is None:
        pytest.fail("audit-bank-full skill not discovered by loader")
    return s


def test_skill_discovered(skill):
    assert skill.name == "audit-bank-full"


def test_priority_is_highest_in_banking_stack(skill, loader):
    """audit-bank-full should outrank single-framework banking skills."""
    assert skill.priority >= 30
    for neighbor in ("pci-dss-audit", "swift-network-security", "atm-security"):
        ns = loader.get_by_name(neighbor)
        if ns is not None:
            assert skill.priority >= ns.priority, (
                f"audit-bank-full ({skill.priority}) should have priority >= "
                f"{neighbor} ({ns.priority}) to win as orchestrator"
            )


def test_required_tools_include_orchestration_core(skill):
    """The skill must reference the compliance-audit + PDF generation tools."""
    required = set(skill.required_tools)
    assert "run_compliance_audit" in required
    assert "generate_compliance_pdf" in required
    assert "run_command" in required
    assert "request_approval" in required


def test_body_references_all_frameworks(skill):
    """The skill body should reference every framework YAML we ship so the
    LLM knows which to route to per host type."""
    body = skill.body.lower()
    for fw_hint in (
        "cis-ubuntu-22.04",
        "cis-debian-12",
        "cis-rhel-9",
        "cis-docker-1.6",
        "cis-windows-server-2022",
        "pci-dss-4.0",
        "swift-csp-2026",
        "bcp-py-res-12-2021",
        "core-banking-hardening",
        "atm-security-bcp-2024",
    ):
        assert fw_hint in body, f"skill body missing {fw_hint!r}"


def test_body_defines_three_phase_flow(skill):
    """Must enforce the deterministic diagnosis → proposal → report flow."""
    body = skill.body.lower()
    # Phase markers
    assert "fase 1" in body or "phase 1" in body
    assert "fase 2" in body or "phase 2" in body
    assert "fase 3" in body or "phase 3" in body
    # Deterministic / LLM separation
    assert "determinístic" in body or "deterministic" in body
    # Approval gate
    assert "esperar" in body or "approval" in body


def test_body_lists_asoban_profiles(skill):
    body = skill.body.lower()
    for profile in ("perfil a", "perfil b", "perfil c"):
        assert profile in body, f"missing {profile}"


def test_body_references_bcp_regulation(skill):
    """Must cite the Paraguay regulatory regime explicitly — core value prop."""
    body = skill.body.lower()
    assert "bcp" in body
    assert "12/2021" in body or "res. 12/2021" in body
    # The one-off ATM regulation
    assert "2024" in body


def test_positive_trigger_matches(loader):
    """Banking-audit intents in Spanish + English should pull the skill in."""
    positive_intents = [
        "auditoría bancaria completa para Banco Plata",
        "audit bank-full perfil B",
        "necesito cumplimiento integral multi-framework",
        "engagement completo con perfil ASOBAN",
        "audit bancario integral con todos los frameworks",
    ]
    for msg in positive_intents:
        matches = loader.match(user_msg=msg)
        names = [m.name for m in matches]
        assert "audit-bank-full" in names, f"audit-bank-full did NOT trigger on {msg!r}; matched: {names[:5]}"


def test_body_warns_about_pii_handling(skill):
    """Regulatory compliance note — no PAN/PIN capture, Ley 6534/2020."""
    body = skill.body.lower()
    assert "pan" in body or "pin" in body
    assert "6534" in body or "datos personales" in body
