"""F147 — Skill auto-update tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from kryon.skills.updater import UpdateResult, update_from_git

_VALID_SKILL = """---
name: test-skill
description: "A test skill"
triggers:
  tech: ["x"]
  ports: [80]
  keywords: ["test"]
priority: 50
---

# Body
"""


_INVALID_NO_FRONTMATTER = """# Just a markdown file with no frontmatter
"""


def _populate_fake_repo(repo_root: Path, files: dict[str, str]) -> None:
    """Helper: create a fake repo dir layout with playbooks/."""
    playbooks = repo_root / "playbooks"
    playbooks.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (playbooks / name).write_text(content, encoding="utf-8")


def test_clone_failure_returns_failed_result(tmp_path):
    def _bad_clone(*args, **kwargs):
        class _P:
            returncode = 128
            stderr = "fatal: repo not found"
            stdout = ""

        return _P()

    with patch("kryon.skills.updater.subprocess.run", side_effect=_bad_clone):
        result = update_from_git(
            "https://github.com/no/such/repo.git",
            local_playbooks_dir=tmp_path / "local",
        )
    assert result.added == []
    assert any(name == "__clone__" for name, _ in result.failed)


def test_missing_playbooks_subdir_reported(tmp_path):
    """Simulate a successful clone but the repo doesn't contain
    a ``playbooks/`` directory."""

    def fake_clone(cmd, **kwargs):
        # Create the empty clone target dir to fake "git clone" success
        # without the expected playbooks subdir.
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)

        class _P:
            returncode = 0
            stderr = ""
            stdout = ""

        return _P()

    with patch("kryon.skills.updater.subprocess.run", side_effect=fake_clone):
        result = update_from_git("https://repo", local_playbooks_dir=tmp_path / "local")
    assert any(name == "__subdir__" for name, _ in result.failed)


def test_valid_skill_added(tmp_path):
    """Simulate clone by writing the fake repo into the temp clone dir
    that update_from_git uses (via mocked tempfile.TemporaryDirectory)."""

    def fake_clone(cmd, **kwargs):
        dest = Path(cmd[-1])
        _populate_fake_repo(dest, {"test-skill.md": _VALID_SKILL})

        class _P:
            returncode = 0
            stderr = ""
            stdout = ""

        return _P()

    local = tmp_path / "local"
    with patch("kryon.skills.updater.subprocess.run", side_effect=fake_clone):
        result = update_from_git("https://repo", local_playbooks_dir=local)

    assert "test-skill.md" in list(result.added)
    assert (local / "test-skill.md").exists()


def test_existing_skill_skipped_without_force(tmp_path):
    local = tmp_path / "local"
    local.mkdir()
    (local / "test-skill.md").write_text("# existing local copy", encoding="utf-8")

    def fake_clone(cmd, **kwargs):
        dest = Path(cmd[-1])
        _populate_fake_repo(dest, {"test-skill.md": _VALID_SKILL})

        class _P:
            returncode = 0
            stderr = ""
            stdout = ""

        return _P()

    with patch("kryon.skills.updater.subprocess.run", side_effect=fake_clone):
        result = update_from_git("https://repo", local_playbooks_dir=local)

    assert result.added == []
    assert any(name == "test-skill.md" for name, _ in result.skipped)
    # Local content preserved.
    assert "existing local copy" in (local / "test-skill.md").read_text(encoding="utf-8")


def test_existing_skill_overwritten_with_force(tmp_path):
    local = tmp_path / "local"
    local.mkdir()
    (local / "test-skill.md").write_text("# old", encoding="utf-8")

    def fake_clone(cmd, **kwargs):
        dest = Path(cmd[-1])
        _populate_fake_repo(dest, {"test-skill.md": _VALID_SKILL})

        class _P:
            returncode = 0
            stderr = ""
            stdout = ""

        return _P()

    with patch("kryon.skills.updater.subprocess.run", side_effect=fake_clone):
        result = update_from_git("https://repo", local_playbooks_dir=local, force=True)

    assert "test-skill.md" in result.updated
    # Upstream content now present.
    assert "name: test-skill" in (local / "test-skill.md").read_text(encoding="utf-8")


def test_invalid_skill_reported(tmp_path):
    def fake_clone(cmd, **kwargs):
        dest = Path(cmd[-1])
        _populate_fake_repo(dest, {"bad.md": _INVALID_NO_FRONTMATTER})

        class _P:
            returncode = 0
            stderr = ""
            stdout = ""

        return _P()

    with patch("kryon.skills.updater.subprocess.run", side_effect=fake_clone):
        result = update_from_git("https://repo", local_playbooks_dir=tmp_path / "local")

    assert result.added == []
    assert any(name == "bad.md" and "frontmatter" in err for name, err in result.failed)


def test_update_result_total_added():
    r = UpdateResult(added=["a", "b"], updated=["c"])
    assert r.total_added == 3
