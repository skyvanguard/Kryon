"""F176 — Append-only partial finding persistence tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryon.validation.findings_persistence import (
    append_partial_finding,
    clear_partial_findings,
    partial_findings_dir,
    read_partial_findings,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_partial_dir(monkeypatch, tmp_path):
    """Each test gets a fresh tmp partial dir + engagement id."""
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_ENGAGEMENT_ID", "test-eid-001")
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS", "true")
    return tmp_path


# ---------------------------------------------------------------------------
# Happy path — single append + read back
# ---------------------------------------------------------------------------


def test_append_creates_file_and_writes_line(_isolate_partial_dir):
    f = {"id": "fnd_1", "cwe": "CWE-79", "message": "XSS in /search"}
    ok = append_partial_finding(f)
    assert ok is True

    path = _isolate_partial_dir / "test-eid-001.jsonl"
    assert path.exists()
    assert path.read_text(encoding="utf-8").count("\n") == 1


def test_round_trip_single_finding(_isolate_partial_dir):
    f = {"id": "fnd_1", "cwe": "CWE-79", "message": "XSS"}
    append_partial_finding(f)
    loaded = read_partial_findings("test-eid-001")
    assert len(loaded) == 1
    assert loaded[0] == f


def test_multiple_findings_append(_isolate_partial_dir):
    findings = [
        {"id": "a", "cwe": "CWE-79"},
        {"id": "b", "cwe": "CWE-200"},
        {"id": "c", "cwe": "CWE-89"},
    ]
    for f in findings:
        append_partial_finding(f)

    loaded = read_partial_findings("test-eid-001")
    assert len(loaded) == 3
    assert [f["id"] for f in loaded] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Engagement isolation — each engagement gets its own file
# ---------------------------------------------------------------------------


def test_different_engagements_separate_files(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS", "true")

    monkeypatch.setenv("KRYON_ENGAGEMENT_ID", "eng-A")
    append_partial_finding({"id": "a1"})
    monkeypatch.setenv("KRYON_ENGAGEMENT_ID", "eng-B")
    append_partial_finding({"id": "b1"})
    append_partial_finding({"id": "b2"})

    assert [f["id"] for f in read_partial_findings("eng-A")] == ["a1"]
    assert [f["id"] for f in read_partial_findings("eng-B")] == ["b1", "b2"]


# ---------------------------------------------------------------------------
# Gating — no engagement id → no-op, no file
# ---------------------------------------------------------------------------


def test_missing_engagement_id_silent_noop(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS_DIR", str(tmp_path))
    monkeypatch.delenv("KRYON_ENGAGEMENT_ID", raising=False)
    ok = append_partial_finding({"id": "a"})
    assert ok is False
    assert list(tmp_path.iterdir()) == []


def test_empty_engagement_id_silent_noop(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_ENGAGEMENT_ID", "")
    ok = append_partial_finding({"id": "a"})
    assert ok is False


def test_disabled_via_env(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_ENGAGEMENT_ID", "eng-X")
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS", "false")
    ok = append_partial_finding({"id": "a"})
    assert ok is False


# ---------------------------------------------------------------------------
# Invalid input — non-dict drops
# ---------------------------------------------------------------------------


def test_non_dict_input_returns_false(_isolate_partial_dir):
    assert append_partial_finding("not a dict") is False  # type: ignore[arg-type]
    assert append_partial_finding(None) is False  # type: ignore[arg-type]
    assert append_partial_finding([1, 2]) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Recovery — robust to malformed lines mixed in
# ---------------------------------------------------------------------------


def test_read_skips_malformed_lines(_isolate_partial_dir):
    path = _isolate_partial_dir / "test-eid-001.jsonl"
    path.write_text(
        '{"id":"good1"}\n'
        "not valid json\n"
        '{"id":"good2"}\n'
        "\n"  # blank line
        '"a string, not a dict"\n'  # parses but isn't dict
        '{"id":"good3"}\n',
        encoding="utf-8",
    )
    loaded = read_partial_findings("test-eid-001")
    assert [f["id"] for f in loaded] == ["good1", "good2", "good3"]


def test_read_nonexistent_returns_empty(_isolate_partial_dir):
    assert read_partial_findings("does-not-exist") == []


# ---------------------------------------------------------------------------
# Engagement id sanitization
# ---------------------------------------------------------------------------


def test_engagement_id_with_special_chars_sanitized(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_ENGAGEMENT_ID", "engagement/with:weird*chars")
    monkeypatch.setenv("KRYON_PARTIAL_FINDINGS", "true")
    ok = append_partial_finding({"id": "a"})
    assert ok is True
    # Only one file created, all separators replaced with underscores.
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    assert "/" not in files[0].name
    assert ":" not in files[0].name
    assert "*" not in files[0].name


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------


def test_clear_removes_file(_isolate_partial_dir):
    append_partial_finding({"id": "a"})
    path = _isolate_partial_dir / "test-eid-001.jsonl"
    assert path.exists()

    removed = clear_partial_findings("test-eid-001")
    assert removed is True
    assert not path.exists()


def test_clear_nonexistent_returns_false(_isolate_partial_dir):
    assert clear_partial_findings("does-not-exist") is False


# ---------------------------------------------------------------------------
# Encoding — unicode preserved
# ---------------------------------------------------------------------------


def test_unicode_preserved(_isolate_partial_dir):
    f = {"id": "fnd", "message": "Inyección SQL en /búsqueda — vé también /usuario/ñoño"}
    append_partial_finding(f)
    loaded = read_partial_findings("test-eid-001")
    assert loaded[0]["message"] == f["message"]


# ---------------------------------------------------------------------------
# partial_findings_dir env default
# ---------------------------------------------------------------------------


def test_partial_findings_dir_default(monkeypatch):
    monkeypatch.delenv("KRYON_PARTIAL_FINDINGS_DIR", raising=False)
    d = partial_findings_dir()
    assert d == Path(".kryon") / "partial_findings"
