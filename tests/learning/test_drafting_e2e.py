"""End-to-end tests for the Fase 1 skill drafting flow.

Covers the full path from a successful engagement experience to:
  1. Synthesizing a SkillDraft.
  2. Writing it to ~/.kryon/drafts/ (overridden to tmp_path).
  3. Listing it via the REPL `/skill drafts` handler.
  4. Reviewing it via `/skill review`.
  5. Promoting it to playbooks/_drafts/.
  6. Discarding a separate draft via `/skill discard`.

These tests exercise the handlers' data path; they don't assert on
console output (rich panels are tested implicitly by absence of
exceptions).
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def isolated_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    """Override drafts dir + playbooks dir so promotion writes to tmp."""
    drafts = tmp_path / "drafts"
    playbooks = tmp_path / "playbooks"
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(drafts))

    # Patch the module-level _PROMOTED_DRAFTS_DIR in skill.py so promotion
    # lands inside tmp_path. Importing also gives us the SkillCommand class.
    from kryon.repl.commands import skill as skill_cmd_mod

    promoted_dir = playbooks / "_drafts"
    monkeypatch.setattr(skill_cmd_mod, "_PROMOTED_DRAFTS_DIR", promoted_dir)

    return {"drafts": drafts, "playbooks": playbooks, "promoted": promoted_dir}


def _success_experience(eid: str = "eng_e2e_001") -> dict:
    return {
        "id": eid,
        "created_at": "2026-04-28T17:00:00+00:00",
        "target_profile": {
            "host": "victim.example.com",
            "ports": [80, 443],
            "tech": ["wordpress"],
            "os_hint": "linux",
        },
        "chain": [
            {"tool": "nmap", "args": "-sV", "status": "ok", "output": "open: 80,443"},
            {"tool": "whatweb", "args": "x", "status": "ok", "output": "wp"},
            {"tool": "exploit_wp_xss", "args": "x", "status": "ok", "output": "uid=33"},
        ],
        "outcome": "success",
        "outcome_signals": {"shell_gained": True, "directories_found": 5},
        "agent_path": ["recon-scout"],
        "duration_s": 240,
        "summary": "wp xss → shell on victim.example.com",
    }


# ---------- Synthesize → write → list ----------


def test_synthesize_persists_draft_and_appears_in_list(isolated_dirs) -> None:
    from kryon.learning.draft_writer import (
        list_existing_names,
        try_synthesize_and_persist,
    )

    path = try_synthesize_and_persist(_success_experience())
    assert path is not None
    assert path.exists()
    assert path.name in {p.name for p in isolated_dirs["drafts"].iterdir()}
    assert path.stem in list_existing_names()


def test_drafts_list_handler_runs_without_error(isolated_dirs) -> None:
    """Handler should not raise even with no drafts present."""
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    # No drafts yet — empty case.
    assert cmd.handle_drafts() is True


def test_drafts_list_handler_runs_with_one_draft(isolated_dirs) -> None:
    from kryon.learning.draft_writer import try_synthesize_and_persist
    from kryon.repl.commands.skill import SkillCommand

    try_synthesize_and_persist(_success_experience())

    cmd = SkillCommand()
    assert cmd.handle_drafts() is True


# ---------- Review ----------


def test_review_handler_shows_existing_draft(isolated_dirs) -> None:
    from kryon.learning.draft_writer import try_synthesize_and_persist
    from kryon.repl.commands.skill import SkillCommand

    path = try_synthesize_and_persist(_success_experience())
    assert path is not None

    cmd = SkillCommand()
    assert cmd.handle_review([path.stem]) is True


def test_review_handler_handles_missing_draft(isolated_dirs) -> None:
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    # Should not raise; should not return False (it's a soft "no result").
    assert cmd.handle_review(["does-not-exist"]) is True


def test_review_handler_rejects_no_args(isolated_dirs) -> None:
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    assert cmd.handle_review([]) is False


# ---------- Promote ----------


def test_promote_moves_draft_to_playbooks_drafts_dir(isolated_dirs) -> None:
    from kryon.learning.draft_writer import (
        list_existing_names,
        try_synthesize_and_persist,
    )
    from kryon.repl.commands.skill import SkillCommand

    path = try_synthesize_and_persist(_success_experience())
    assert path is not None
    name = path.stem

    cmd = SkillCommand()
    assert cmd.handle_promote([name]) is True

    # Source removed from drafts dir
    assert name not in list_existing_names()
    assert not path.exists()
    # Target file created in promoted dir
    target = isolated_dirs["promoted"] / f"{name}.md"
    assert target.exists()
    # Content survived the move
    content = target.read_text(encoding="utf-8")
    assert "_provenance" in content


def test_promote_refuses_to_overwrite_existing(isolated_dirs) -> None:
    from kryon.learning.draft_writer import try_synthesize_and_persist
    from kryon.repl.commands.skill import SkillCommand

    path = try_synthesize_and_persist(_success_experience())
    assert path is not None
    name = path.stem

    # Pre-create the target so promote should refuse.
    target = isolated_dirs["promoted"] / f"{name}.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("PRE-EXISTING\n", encoding="utf-8")

    cmd = SkillCommand()
    assert cmd.handle_promote([name]) is True  # soft "no overwrite" — returns True

    # Target unchanged
    assert target.read_text(encoding="utf-8") == "PRE-EXISTING\n"
    # Source draft NOT deleted (we refused to clobber)
    assert path.exists()


def test_promote_drafts_skipped_by_loader(isolated_dirs) -> None:
    """The crucial guarantee: promoted drafts MUST NOT auto-load as
    active skills (they live in _drafts/ which the loader ignores)."""
    from kryon.learning.draft_writer import try_synthesize_and_persist
    from kryon.repl.commands.skill import SkillCommand
    from kryon.skills.loader import SkillLoader

    path = try_synthesize_and_persist(_success_experience())
    assert path is not None
    name = path.stem

    cmd = SkillCommand()
    assert cmd.handle_promote([name]) is True

    # Point the loader at the tmp playbooks dir and confirm the promoted
    # draft does NOT appear in scan().
    loader = SkillLoader(skill_dirs=[isolated_dirs["playbooks"]])
    skills = loader.scan()
    names_loaded = {s.name for s in skills}
    assert name not in names_loaded


# ---------- Discard ----------


def test_discard_removes_draft(isolated_dirs) -> None:
    from kryon.learning.draft_writer import (
        list_existing_names,
        try_synthesize_and_persist,
    )
    from kryon.repl.commands.skill import SkillCommand

    path = try_synthesize_and_persist(_success_experience())
    assert path is not None
    name = path.stem

    cmd = SkillCommand()
    assert cmd.handle_discard([name]) is True
    assert name not in list_existing_names()
    assert not path.exists()


def test_discard_handles_missing(isolated_dirs) -> None:
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    assert cmd.handle_discard(["never-was"]) is True
