"""Smoke tests for the skill loader — F77.B.

Only verifies that the loader finds playbooks, matches on basic
signals, and never regresses on total count. Not a deep behavioral
spec — that lives in the per-skill tests.
"""

from __future__ import annotations

import pytest

from kryon.skills.loader import SkillLoader


@pytest.fixture(scope="module")
def loader() -> SkillLoader:
    return SkillLoader()


def test_loader_finds_playbooks(loader: SkillLoader) -> None:
    """The playbook directory must yield at least the core + banking skills.

    60 is a conservative floor; actual count is ~67. Tripping this fails
    loud if a playbook subdir silently disappears.
    """
    skills = loader.scan()
    assert len(skills) >= 60, (
        f"Expected ≥60 skills, got {len(skills)}. A playbook dir may be missing."
    )


def test_match_returns_empty_on_noise(loader: SkillLoader) -> None:
    """Gibberish input shouldn't match any keyword-triggered skill.

    Base skills (with empty triggers) still match — that's by design.
    """
    skills = loader.match(user_msg="xyzzy plover frobnicate")
    # At most the base skills; none should be keyword-matched.
    for s in skills:
        if s.triggers.get("keywords"):
            user_lower = "xyzzy plover frobnicate".lower()
            hit = any(kw.lower() in user_lower for kw in s.triggers["keywords"])
            assert not hit, f"noise matched keyword in {s.name}"


def test_match_web_intent(loader: SkillLoader) -> None:
    """"audita juice shop" should surface a web-pentest-class skill."""
    skills = loader.match(user_msg="audita juice shop OWASP")
    names = [s.name for s in skills]
    assert any(
        "web" in n.lower() or "pentest" in n.lower() or "owasp" in n.lower()
        for n in names
    ), f"no web/pentest skill surfaced: {names}"


def test_get_by_name_known_skill(loader: SkillLoader) -> None:
    """recon-scout must resolve by name (fallback path in unified_agent)."""
    skill = loader.get_by_name("recon-scout")
    assert skill is not None
    assert skill.name == "recon-scout"


def test_required_tool_names_is_set(loader: SkillLoader) -> None:
    skills = loader.scan()[:3]
    tool_names = loader.required_tool_names(skills)
    assert isinstance(tool_names, set)
