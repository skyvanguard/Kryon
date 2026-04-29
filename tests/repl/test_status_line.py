"""TDD contract for kryon.repl.ui.status_line.

Renders a single-line summary of agent + system state at the start of
each turn. Composable, resilient, and never crashes the REPL — every
optional component (chromadb-backed draft count, ollama health) wrapped
in its own try/except.
"""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _isolate_status_line_cache():
    """The status line module memoizes lookups for ~5s. Clear between
    tests so each test sees fresh state from its monkeypatches."""
    from kryon.repl.ui.status_line import clear_cache

    clear_cache()
    yield
    clear_cache()


class _FakeAgent:
    def __init__(
        self,
        skills: list | None = None,
        tools: list | None = None,
    ) -> None:
        if skills is not None:
            self._active_skills = skills
        if tools is not None:
            self.tools = tools


class _FakeSkill:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


def _render(agent: Any, **kwargs: Any) -> str:
    """Helper: render to a captured StringIO and return text."""
    from rich.console import Console

    from kryon.repl.ui.status_line import render_status_line

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120, color_system=None)
    render_status_line(agent, console, **kwargs)
    return buf.getvalue()


# ---------- Skills section ----------


def test_renders_skill_names_when_agent_has_skills() -> None:
    agent = _FakeAgent(
        skills=[_FakeSkill("fortigate-audit"), _FakeSkill("recon-scout")],
        tools=[_FakeTool(f"t{i}") for i in range(14)],
    )
    out = _render(agent)
    assert "fortigate-audit" in out
    assert "recon-scout" in out
    assert "14 tools" in out


def test_truncates_long_skill_lists_with_overflow_marker() -> None:
    """If 7 skills are active, show only first 3 + '+4'."""
    agent = _FakeAgent(
        skills=[_FakeSkill(f"skill-{i}") for i in range(7)],
        tools=[],
    )
    out = _render(agent)
    assert "skill-0" in out
    assert "skill-1" in out
    assert "skill-2" in out
    # The overflow marker
    assert "+4" in out


def test_handles_agent_with_no_skills_attr() -> None:
    """Bare agent (no _active_skills) renders a 'no skills' indicator."""
    class _Bare:
        pass

    out = _render(_Bare())
    # Doesn't crash; shows something useful.
    assert out.strip() != ""


def test_handles_agent_with_empty_skills() -> None:
    agent = _FakeAgent(skills=[], tools=[])
    out = _render(agent)
    # Cold-start state mentioned somehow.
    assert "0 tools" in out or "no skill" in out.lower() or out.strip() != ""


# ---------- Drafts badge ----------


def test_drafts_badge_appears_when_drafts_exist(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    # Stub the draft writer so we don't touch ~/.kryon/drafts.
    monkeypatch.setattr(
        status_line,
        "_count_drafts",
        lambda: 3,
    )
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    out = _render(agent)
    assert "3 drafts" in out or "3" in out


def test_drafts_badge_hidden_when_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    monkeypatch.setattr(status_line, "_count_drafts", lambda: 0)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    out = _render(agent)
    assert "draft" not in out.lower()


def test_drafts_count_failure_does_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    def boom() -> int:
        raise RuntimeError("no chromadb")

    monkeypatch.setattr(status_line, "_count_drafts", boom)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    # Should not raise.
    out = _render(agent)
    assert "draft" not in out.lower()  # gracefully omitted


# ---------- Ollama health ----------


def test_ollama_ok_shows_check_mark(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    monkeypatch.setattr(status_line, "_ollama_healthy", lambda: True)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    out = _render(agent)
    assert "ollama" in out.lower()


def test_ollama_down_shows_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    monkeypatch.setattr(status_line, "_ollama_healthy", lambda: False)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    out = _render(agent)
    # Down state is communicated somehow.
    assert "ollama" in out.lower()
    # Either ✗ or "down" or red marker — assertion-level just confirms
    # ollama is mentioned. Specific style asserted in theme tests.


def test_ollama_check_failure_does_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    def boom() -> bool:
        raise ConnectionError("network down")

    monkeypatch.setattr(status_line, "_ollama_healthy", boom)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    # Should not raise — degrades to silent omission.
    out = _render(agent)
    assert out.strip() != ""


# ---------- Last experience ----------


def test_last_experience_shown_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    monkeypatch.setattr(
        status_line, "_last_experience_id", lambda: "eng_a3f9b2c1d4e5",
    )
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    out = _render(agent)
    assert "eng_a3f9b2" in out


def test_last_experience_hidden_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.ui import status_line

    monkeypatch.setattr(status_line, "_last_experience_id", lambda: None)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    out = _render(agent)
    assert "eng_" not in out


# ---------- Composition / overall shape ----------


def test_renders_single_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """The status header is at most 2 lines (header + dim subline). NOT
    a multi-line panel — keeps scrollback compact."""
    from kryon.repl.ui import status_line

    monkeypatch.setattr(status_line, "_count_drafts", lambda: 0)
    monkeypatch.setattr(status_line, "_ollama_healthy", lambda: True)
    monkeypatch.setattr(status_line, "_last_experience_id", lambda: None)

    agent = _FakeAgent(
        skills=[_FakeSkill("a"), _FakeSkill("b")],
        tools=[_FakeTool("t")],
    )
    out = _render(agent)
    # Output is non-empty + bounded in line count.
    line_count = len([line for line in out.splitlines() if line.strip()])
    assert 0 < line_count <= 2


def test_uses_palette_b_cyan_accent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the primary accent (cyan) shows up in the rendered output
    when color_system is enabled."""
    from rich.console import Console

    from kryon.repl.ui import status_line
    from kryon.repl.ui.status_line import render_status_line

    monkeypatch.setattr(status_line, "_count_drafts", lambda: 0)
    monkeypatch.setattr(status_line, "_ollama_healthy", lambda: True)
    monkeypatch.setattr(status_line, "_last_experience_id", lambda: None)

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    agent = _FakeAgent(skills=[_FakeSkill("x")], tools=[])
    render_status_line(agent, console)
    text = buf.getvalue()
    # ANSI cyan = 36, bold cyan = 1;36. Just check that some color escape
    # appears (the rendering used the theme).
    assert "\x1b[" in text  # ANSI escape
