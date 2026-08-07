"""Regression: source-review enumeration must not follow escaping symlinks.

`kryon investigate <code_path>` points the reviewer at UNTRUSTED cloned
target code. A symlink inside that tree pointing at a local secret would
otherwise have its real content read and shipped to the review model
(possibly a remote/frontier endpoint) — a file-exfiltration primitive
triggered by merely auditing someone else's source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryon.intelligence.source_review import enumerate_source_files


def _write(p: Path, content: str = "x = 1\n") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_enumerate_rejects_symlinked_file_escaping_root(tmp_path: Path) -> None:
    secret = _write(tmp_path / "outside" / "id_rsa.py", "PRIVATE KEY MATERIAL\n")
    tree = tmp_path / "repo"
    _write(tree / "app.py", "x = 1\n")
    link = tree / "leak.py"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")

    names = {p.name for p in enumerate_source_files(tree)}
    assert "app.py" in names
    assert "leak.py" not in names, "symlink escaping root was included (exfil risk)"


def test_enumerate_does_not_descend_into_symlinked_dir(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _write(outside / "secret.py", "SECRET\n")
    tree = tmp_path / "repo"
    _write(tree / "app.py", "x = 1\n")
    try:
        (tree / "vendored").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")

    rels = {p.name for p in enumerate_source_files(tree)}
    assert "app.py" in rels
    assert "secret.py" not in rels, "descended into a symlinked dir outside root"
