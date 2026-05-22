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
    assert len(skills) >= 60, f"Expected ≥60 skills, got {len(skills)}. A playbook dir may be missing."


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
    """ "audita juice shop" should surface a web/api-security-class skill.

    F203.AD — expanded acceptable names: post-F202.AF imported skills
    include `api-gateway-aws-waf` and `api-security-owasp-top-10`, both
    legitimately matched by "owasp" keyword. Either satisfies the
    intent ("user wants a web pentest playbook").
    """
    skills = loader.match(user_msg="audita juice shop OWASP")
    names = [s.name for s in skills]
    valid_tokens = ("web", "pentest", "owasp", "api-security", "api-gateway", "waf")
    assert any(
        any(tok in n.lower() for tok in valid_tokens) for n in names
    ), f"no web/api-security/pentest skill surfaced: {names}"


# ---------- F77.E — whole-word keyword matching ----------


def test_short_keyword_does_not_match_inside_word(loader: SkillLoader) -> None:
    """Pre-fix: keyword "ad" (active-directory-recon) matched
    "segurid**ad**" via substring. Now whole-word — must NOT match."""
    skills = loader.match(user_msg="análisis de seguridad de la web")
    names = [s.name for s in skills]
    assert "active-directory-recon" not in names, f"'ad' keyword matched 'seguridad' (substring bug): {names}"


def test_short_keyword_still_matches_as_whole_word(loader: SkillLoader) -> None:
    """The whole-word fix must NOT break legitimate short-keyword matches."""
    skills = loader.match(user_msg="enumerate ad domain controllers")
    names = [s.name for s in skills]
    assert "active-directory-recon" in names, f"'ad' as whole word should still match: {names}"


def test_natural_spanish_web_prompt_loads_web_pentest(loader: SkillLoader) -> None:
    """Operator types a natural Spanish prompt — web-pentest must surface."""
    skills = loader.match(user_msg="quiero un análisis de seguridad de la web: example.com")
    names = [s.name for s in skills]
    assert "web-pentest" in names, f"natural Spanish web-security prompt didn't surface web-pentest: {names}"


def test_fix_keyword_does_not_match_prefix_or_suffix(loader: SkillLoader) -> None:
    """`fix` keyword (safe-modification) must not eat 'pre**fix**' / 'su**ffix**'."""
    skills = loader.match(user_msg="prefix this path with /api and add a suffix")
    names = [s.name for s in skills]
    assert "safe-modification" not in names, f"'fix' keyword matched prefix/suffix (substring bug): {names}"


def test_unicode_accented_keyword_matches(loader: SkillLoader) -> None:
    """`análisis` (with acute) must match in real Spanish text."""
    skills = loader.match(user_msg="hagamos un análisis del host")
    names = [s.name for s in skills]
    assert "recon-scout" in names, f"accented Spanish keyword should match: {names}"


def test_substring_within_unicode_word_does_not_match(loader: SkillLoader) -> None:
    """`ad` must not match inside 'seguridad' even with accented Spanish."""
    skills = loader.match(user_msg="evaluemos la seguridad")
    names = [s.name for s in skills]
    assert "active-directory-recon" not in names


def test_get_by_name_known_skill(loader: SkillLoader) -> None:
    """recon-scout must resolve by name (fallback path in unified_agent)."""
    skill = loader.get_by_name("recon-scout")
    assert skill is not None
    assert skill.name == "recon-scout"


def test_required_tool_names_is_set(loader: SkillLoader) -> None:
    skills = loader.scan()[:3]
    tool_names = loader.required_tool_names(skills)
    assert isinstance(tool_names, set)
