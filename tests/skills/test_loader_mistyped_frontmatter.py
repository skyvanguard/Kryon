"""Regression: a single mistyped playbook must not crash the whole loader.

`priority`/`ports` were `int()`-converted outside any try/except, so one
auto-synthesized draft with `priority: high` or `ports: [any]` would raise
ValueError all the way up through create_unified_agent() / `kryon
investigate` — taking down skill loading for EVERY skill, not just the bad
one. The parser must degrade per-field instead.
"""

from __future__ import annotations

from pathlib import Path

from kryon.skills.loader import _parse_skill_file


def _make_skill(tmp_path: Path, frontmatter: str, name: str = "bad.md") -> Path:
    md = tmp_path / name
    md.write_text(f"---\n{frontmatter}---\nbody here\n", encoding="utf-8")
    return md


def test_mistyped_priority_defaults_instead_of_crashing(tmp_path: Path) -> None:
    md = _make_skill(
        tmp_path,
        "name: bad-skill\n"
        "priority: high\n"  # not an int
        "triggers:\n"
        "  tech: [nginx]\n"
        "  ports: [80]\n"
        "  keywords: [foo]\n",
    )
    skill = _parse_skill_file(md)  # must NOT raise
    assert skill is not None
    assert skill.priority == 50  # defaulted, not crashed
    assert skill.name == "bad-skill"


def test_mistyped_port_is_dropped_valid_ones_kept(tmp_path: Path) -> None:
    md = _make_skill(
        tmp_path,
        "name: bad-ports\n"
        "priority: 10\n"
        "triggers:\n"
        "  tech: [apache]\n"
        "  ports: [any, 443]\n"  # 'any' is not an int
        "  keywords: [bar]\n",
    )
    skill = _parse_skill_file(md)  # must NOT raise
    assert skill is not None
    assert skill.priority == 10
    assert skill.triggers["ports"] == [443]  # 'any' dropped, 443 kept


def test_nonstring_keyword_is_coerced_not_crashing(tmp_path: Path) -> None:
    # A bare int keyword (e.g. a status code / CVE year typo) must not later crash
    # SkillLoader.match() with "'int' object has no attribute 'lower'" — which took
    # down matching for ALL skills, not just the bad one.
    md = _make_skill(
        tmp_path,
        "name: bad-kw\n"
        "priority: 10\n"
        "triggers:\n"
        "  tech: [80, nginx]\n"  # 80 is an int
        "  keywords: [403, sqli]\n",  # 403 is an int
        name="badkw.md",
    )
    skill = _parse_skill_file(md)
    assert skill is not None
    assert all(isinstance(k, str) for k in skill.triggers["keywords"])
    assert "403" in skill.triggers["keywords"] and "sqli" in skill.triggers["keywords"]
    assert all(isinstance(t, str) for t in skill.triggers["tech"])
    # And matching must not raise on it.
    from kryon.skills.loader import _keyword_matches

    assert _keyword_matches(skill.triggers["keywords"][0], "algún texto 403") is True


def test_scalar_required_tools_becomes_single_element_list(tmp_path: Path) -> None:
    # `required_tools: run_command` (scalar, no list) must NOT be iterated
    # character-by-character (which silently dropped every tool).
    md = _make_skill(
        tmp_path,
        "name: scalar-req\n"
        "required_tools: run_command\n"  # scalar
        "triggers:\n"
        "  keywords: [x]\n",
        name="scalarreq.md",
    )
    skill = _parse_skill_file(md)
    assert skill.required_tools == ["run_command"]


def test_scalar_forbidden_tools_not_split_into_chars(tmp_path: Path) -> None:
    # `forbidden_tools: execute_code` (scalar) must stay a 1-element tuple, else
    # the sandbox-bypass guard silently blocks nothing (it'd subtract single chars).
    md = _make_skill(
        tmp_path,
        "name: scalar-forbid\n"
        "forbidden_tools: execute_code\n"  # scalar
        "triggers:\n"
        "  keywords: [x]\n",
        name="scalarforbid.md",
    )
    skill = _parse_skill_file(md)
    assert skill.forbidden_tools == ("execute_code",)
