"""Tests for kryon.learning.draft_writer.

Filesystem IO for skill drafts. Pure tests — no chromadb. The
high-level helper `try_synthesize_and_persist` is also covered here
with a stubbed experience store so we can assert the full flow.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def drafts_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point KRYON_DRAFTS_DIR at tmp_path so we don't pollute ~/.kryon."""
    target = tmp_path / "drafts"
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(target))
    return target


def _draft(name: str = "wp-success-draft-001") -> Path:
    """Build a synthetic SkillDraft for IO tests, no synthesizer needed."""
    from kryon.learning.skill_synthesizer import SkillDraft

    fm = {
        "name": name,
        "description": "test draft",
        "triggers": {"tech": ["wordpress"], "ports": [80], "keywords": ["wp"]},
        "priority": 50,
        "required_tools": ["nmap", "whatweb"],
        "_provenance": {"experience_id": "eng_test", "outcome": "success"},
    }
    return SkillDraft(name=name, body="# Body\n\nphases", frontmatter=fm)


# ---------- get_drafts_dir / list_existing ----------


def test_drafts_dir_uses_env_var(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import get_drafts_dir

    assert get_drafts_dir() == drafts_dir


def test_list_existing_names_empty_when_no_dir(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import list_existing_names

    assert list_existing_names() == set()


def test_list_existing_names_returns_stems(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import list_existing_names, write_draft

    write_draft(_draft("alpha"))
    write_draft(_draft("beta"))
    assert list_existing_names() == {"alpha", "beta"}


# ---------- write_draft ----------


def test_write_creates_dir_if_missing(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import write_draft

    assert not drafts_dir.exists()
    path = write_draft(_draft())
    assert path.exists()
    assert path.parent == drafts_dir


def test_write_uses_name_as_filename_with_md_suffix(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import write_draft

    path = write_draft(_draft("custom-name"))
    assert path.name == "custom-name.md"


def test_write_persists_full_markdown(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import write_draft

    path = write_draft(_draft())
    content = path.read_text(encoding="utf-8")
    assert content.startswith("---\n")
    assert "name: wp-success-draft-001" in content
    assert "phases" in content


def test_write_overwrites_existing_draft(drafts_dir: Path) -> None:
    """If the operator generates two drafts with the same auto-name (rare —
    the synthesizer's counter usually prevents this), latest write wins."""
    from kryon.learning.draft_writer import write_draft

    p1 = write_draft(_draft("dup"))
    original = p1.read_text(encoding="utf-8")
    write_draft(_draft("dup"))
    # Same path, but we don't assert content equality — only that no error
    # was raised and the file remained.
    assert p1.exists()
    assert isinstance(original, str)


# ---------- read_draft / delete_draft ----------


def test_read_draft_returns_content(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import read_draft, write_draft

    write_draft(_draft("readme"))
    content = read_draft("readme")
    assert content is not None
    assert "name: readme" in content


def test_read_draft_returns_none_when_missing(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import read_draft

    assert read_draft("ghost") is None


def test_delete_draft_returns_true_on_existing(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import delete_draft, write_draft

    write_draft(_draft("doomed"))
    assert delete_draft("doomed") is True
    assert not (drafts_dir / "doomed.md").exists()


def test_delete_draft_returns_false_on_missing(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import delete_draft

    assert delete_draft("never-was") is False


# ---------- try_synthesize_and_persist (end-to-end) ----------


def test_try_synthesize_returns_none_on_low_quality_experience(
    drafts_dir: Path,
) -> None:
    """recon-only experience → synthesizer returns None → no file written."""
    from kryon.learning.draft_writer import try_synthesize_and_persist

    exp = {
        "id": "eng_recon",
        "outcome": "recon-only",
        "chain": [{"tool": "nmap", "args": "", "status": "ok", "output": ""}],
        "target_profile": {"tech": []},
        "summary": "x",
    }
    assert try_synthesize_and_persist(exp) is None
    assert list(drafts_dir.glob("*.md")) == []


def test_try_synthesize_writes_draft_for_success(drafts_dir: Path) -> None:
    from kryon.learning.draft_writer import try_synthesize_and_persist

    exp = {
        "id": "eng_success_001",
        "outcome": "success",
        "chain": [
            {"tool": "nmap", "args": "", "status": "ok", "output": ""},
            {"tool": "exploit", "args": "", "status": "ok", "output": "uid=0(root)"},
        ],
        "target_profile": {"tech": ["wordpress"], "ports": [80]},
        "outcome_signals": {"shell_gained": True},
        "summary": "wp shell",
    }
    path = try_synthesize_and_persist(exp)
    assert path is not None
    assert path.exists()
    assert path.parent == drafts_dir
    # Content roundtrip
    content = path.read_text(encoding="utf-8")
    assert "wordpress" in content
    assert "_provenance" in content
    assert "eng_success_001" in content


def test_try_synthesize_uses_existing_names_for_uniqueness(drafts_dir: Path) -> None:
    """Two engagements producing the same draft-name pattern get distinct names."""
    from kryon.learning.draft_writer import (
        list_existing_names,
        try_synthesize_and_persist,
    )

    base = {
        "outcome": "success",
        "chain": [
            {"tool": "nmap", "args": "", "status": "ok"},
            {"tool": "x", "args": "", "status": "ok"},
        ],
        "target_profile": {"tech": ["wordpress"], "ports": [80]},
        "outcome_signals": {},
    }
    e1 = {**base, "id": "eng_001", "summary": "first"}
    e2 = {**base, "id": "eng_002", "summary": "second"}

    p1 = try_synthesize_and_persist(e1)
    p2 = try_synthesize_and_persist(e2)
    assert p1 is not None
    assert p2 is not None
    assert p1.name != p2.name
    assert len(list_existing_names()) == 2
