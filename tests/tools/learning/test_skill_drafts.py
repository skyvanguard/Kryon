"""Tests for the self-improvement tools (gap #5): list/promote skill drafts.

Uses KRYON_DRAFTS_DIR + a monkeypatched staging dir, so nothing touches
~/.kryon or the repo's playbooks.
"""

from __future__ import annotations

from kryon.tools.learning import skill_drafts as sd
from kryon.tools.learning.skill_drafts import _list_impl, _promote_impl, _summary


def test_summary_from_frontmatter():
    assert _summary('---\nname: x\ndescription: "Hunt SQLi in PHP"\n---\nbody') == "Hunt SQLi in PHP"


def test_summary_falls_back_to_first_line():
    assert _summary("# heading\n\nFirst real line here").startswith("First real line")


def test_list_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(tmp_path))
    assert "No skill drafts" in _list_impl()


def test_list_with_drafts(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(tmp_path))
    (tmp_path / "sqli-hunter.md").write_text('---\nname: sqli-hunter\ndescription: "Hunt SQLi in PHP"\n---\nbody')
    out = _list_impl()
    assert "sqli-hunter" in out
    assert "Hunt SQLi in PHP" in out


def test_promote_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(tmp_path))
    assert "No draft" in _promote_impl("nope")


def test_promote_success(monkeypatch, tmp_path):
    drafts = tmp_path / "drafts"
    drafts.mkdir()
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(drafts))
    (drafts / "myskill.md").write_text("---\nname: myskill\n---\nbody")
    staging = tmp_path / "staging"
    monkeypatch.setattr(sd, "_staging_dir", lambda: staging)

    out = _promote_impl("myskill")
    assert "Promoted" in out
    assert (staging / "myskill.md").exists()
    # draft is removed from the drafts dir after promotion
    assert not (drafts / "myskill.md").exists()


def test_promote_already_staged(monkeypatch, tmp_path):
    drafts = tmp_path / "drafts"
    drafts.mkdir()
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(drafts))
    (drafts / "dup.md").write_text("---\nname: dup\n---\nbody")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "dup.md").write_text("already here")
    monkeypatch.setattr(sd, "_staging_dir", lambda: staging)

    assert "already promoted" in _promote_impl("dup")


def test_promote_rejects_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(tmp_path))
    # draft_writer.read_draft rejects unsafe names → "No draft"
    out = _promote_impl("../../etc/passwd")
    assert "No draft" in out


# --- wiring -----------------------------------------------------------------


def test_registered_and_offered():
    from pathlib import Path

    import yaml

    from kryon.skills.tool_budget import build_tool_registry

    reg = build_tool_registry()
    assert "list_skill_drafts" in reg
    assert "promote_skill_draft" in reg
    md = Path(__file__).resolve().parents[3] / "src/kryon/skills/playbooks/zero-day/zero-day-hunter.md"
    fm = yaml.safe_load(md.read_text(encoding="utf-8").split("---")[1])
    assert "list_skill_drafts" in fm["required_tools"]
    assert "promote_skill_draft" in fm["required_tools"]
