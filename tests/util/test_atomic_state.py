"""Tests for the atomic, lock-guarded JSON state helpers."""

from __future__ import annotations

import pytest

from kryon.util.atomic_state import read_json_locked, write_json_atomic


@pytest.mark.unit
def test_write_then_read_roundtrips(tmp_path):
    path = tmp_path / "state.json"
    write_json_atomic(path, {"items": [1, 2, 3]})

    assert read_json_locked(path, default={"items": []}) == {"items": [1, 2, 3]}


@pytest.mark.unit
def test_missing_file_returns_default(tmp_path):
    path = tmp_path / "nope.json"
    assert read_json_locked(path, default={"items": []}) == {"items": []}


@pytest.mark.unit
def test_corrupt_file_returns_default(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ this is not json", encoding="utf-8")

    assert read_json_locked(path, default={"k": "v"}) == {"k": "v"}


@pytest.mark.unit
def test_write_creates_parent_dirs(tmp_path):
    path = tmp_path / "deep" / "nested" / "state.json"
    write_json_atomic(path, {"ok": True})

    assert read_json_locked(path, default=None) == {"ok": True}


@pytest.mark.unit
def test_write_leaves_no_temp_files(tmp_path):
    path = tmp_path / "state.json"
    write_json_atomic(path, {"a": 1})
    write_json_atomic(path, {"a": 2})

    leftovers = [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"]
    assert leftovers == [], f"temp files left behind: {leftovers}"
    assert read_json_locked(path, default=None) == {"a": 2}
