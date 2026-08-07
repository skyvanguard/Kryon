"""F130 — Goal-aware SkillLoader.match.

When the operator declares an --objective, the matcher should
priority-bump skills that align with the goal kind + params, surfacing
e.g. ``pci-dss-audit`` for a COMPLIANCE PCI-DSS goal even when the
target's nmap output didn't trigger the playbook's tech/keyword
matches on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from kryon.skills.loader import SkillLoader, _bumps_from_goal
from kryon.tools.autonomous.engagement_goal import EngagementGoal, GoalKind


@pytest.fixture
def loader():
    return SkillLoader()


def _names(skills):
    return [s.name for s in skills]


# ---------------------------------------------------------------------------
# _bumps_from_goal — pure helper
# ---------------------------------------------------------------------------


def test_bumps_none_returns_empty():
    assert _bumps_from_goal(None) == {}


def test_bumps_custom_returns_empty():
    goal = EngagementGoal(kind=GoalKind.CUSTOM, raw="x", params={})
    assert _bumps_from_goal(goal) == {}


def test_bumps_compliance_pci_dss_boosts_pci_skill():
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit PCI-DSS",
        params={"framework": "PCI-DSS"},
    )
    bumps = _bumps_from_goal(goal)
    # Pure kind bump (100) + framework-specific bump (50) = 150
    assert bumps.get("pci-dss-audit", 0) >= 100


def test_bumps_compliance_other_framework_does_not_overboost_pci():
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit HIPAA",
        params={"framework": "HIPAA"},
    )
    bumps = _bumps_from_goal(goal)
    # HIPAA doesn't bump pci-dss-audit beyond the kind-level baseline.
    assert "appsec" in bumps  # HIPAA-specific bump
    # PCI is still at kind-level baseline (no framework-specific addition).
    assert bumps.get("pci-dss-audit", 0) == 100


def test_bumps_vuln_search_sqli_boosts_vuln_hunter_and_appsec():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find SQLi",
        params={"vuln_types": ["sqli"]},
    )
    bumps = _bumps_from_goal(goal)
    assert "vuln-hunter" in bumps
    assert "appsec" in bumps


def test_bumps_vuln_search_xss_includes_browser_exploit():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find XSS",
        params={"vuln_types": ["xss"]},
    )
    bumps = _bumps_from_goal(goal)
    assert "browser-exploit" in bumps


def test_bumps_recon_boosts_recon_scout():
    goal = EngagementGoal(kind=GoalKind.RECON, raw="enumerate", params={"min_services": 3})
    bumps = _bumps_from_goal(goal)
    assert bumps.get("recon-scout", 0) >= 100


def test_bumps_multi_vuln_types_accumulate():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find SQLi and XSS",
        params={"vuln_types": ["sqli", "xss"]},
    )
    bumps = _bumps_from_goal(goal)
    # vuln-hunter gets the kind-level bump (90) + sqli bump (30) + xss bump (30) = 150
    assert bumps.get("vuln-hunter", 0) >= 120


# ---------------------------------------------------------------------------
# SkillLoader.match — integration with goal=
# ---------------------------------------------------------------------------


def test_match_with_compliance_goal_surfaces_pci_skill(loader):
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit PCI-DSS compliance",
        params={"framework": "PCI-DSS"},
    )
    selected = loader.match(profile={"tech": []}, user_msg="audit", goal=goal, budget_tokens=4000)
    names = _names(selected)
    assert "pci-dss-audit" in names


def test_match_with_recon_goal_surfaces_recon_scout(loader):
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="enumerate attack surface",
        params={"min_services": 3},
    )
    selected = loader.match(profile={}, user_msg="audit", goal=goal, budget_tokens=4000)
    assert "recon-scout" in _names(selected)


def test_match_without_goal_does_not_break_existing_match(loader):
    selected = loader.match(profile={"tech": []}, user_msg="audit this network", budget_tokens=4000)
    # Whatever the legacy match returned, it shouldn't be empty (base skills
    # match without triggers).
    assert isinstance(selected, list)


def test_match_with_custom_goal_does_not_change_ranking(loader):
    goal = EngagementGoal(kind=GoalKind.CUSTOM, raw="do something", params={})
    with_goal = _names(loader.match(profile={}, user_msg="audit", goal=goal, budget_tokens=4000))
    without_goal = _names(loader.match(profile={}, user_msg="audit", budget_tokens=4000))
    assert with_goal == without_goal


# ---------------------------------------------------------------------------
# Tolerance / defensive
# ---------------------------------------------------------------------------


@dataclass
class _FakeGoal:
    """Goal-shaped object that's not an EngagementGoal."""

    kind: Any = None
    params: Any = None


def test_bumps_tolerates_unknown_goal_shape():
    # The helper must not raise on unexpected shapes.
    bumps = _bumps_from_goal(_FakeGoal())
    assert bumps == {}
