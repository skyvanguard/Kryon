"""TDD contract for kryon.learning.selection_telemetry.

JSONL log of which skills were selected per turn, alongside the
ranking decision context. Banking-grade auditability: by default the
user message is hashed (not stored verbatim).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def log_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Override KRYON_SELECTION_LOG to a tmp file so we don't touch ~/.kryon."""
    log_path = tmp_path / "selection_log.jsonl"
    monkeypatch.setenv("KRYON_SELECTION_LOG", str(log_path))
    # Make sure the disable flag isn't set from the test runner's env.
    monkeypatch.delenv("KRYON_SELECTION_LOG_DISABLE", raising=False)
    monkeypatch.delenv("KRYON_SELECTION_LOG_PLAINTEXT", raising=False)
    return log_path


def _candidates() -> list[dict]:
    return [
        {"name": "fortigate-audit", "priority": 10, "score": 0.78},
        {"name": "recon-scout", "priority": 12, "score": 0.45},
        {"name": "pci-dss-audit", "priority": 25, "score": None},
    ]


# ---------- Basic write ----------


def test_log_selection_creates_file_and_appends_jsonl(log_dir: Path) -> None:
    from kryon.learning.selection_telemetry import log_selection

    log_selection(
        user_msg="auditá fortigate",
        ranking_mode="hybrid",
        candidates=_candidates(),
        selected=["fortigate-audit", "recon-scout"],
    )
    assert log_dir.exists()
    lines = log_dir.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["ranking_mode"] == "hybrid"
    assert record["selected"] == ["fortigate-audit", "recon-scout"]
    assert record["candidates"] == _candidates()


def test_log_selection_appends_multiple_records(log_dir: Path) -> None:
    from kryon.learning.selection_telemetry import log_selection

    log_selection(user_msg="x", ranking_mode="priority", candidates=[], selected=[])
    log_selection(user_msg="y", ranking_mode="hybrid", candidates=[], selected=[])
    lines = log_dir.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_log_selection_creates_parent_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.learning.selection_telemetry import log_selection

    nested = tmp_path / "deep" / "nested" / "log.jsonl"
    monkeypatch.setenv("KRYON_SELECTION_LOG", str(nested))
    monkeypatch.delenv("KRYON_SELECTION_LOG_DISABLE", raising=False)

    log_selection(user_msg="x", ranking_mode="priority", candidates=[], selected=[])
    assert nested.exists()


# ---------- Privacy ----------


def test_user_msg_is_hashed_by_default(log_dir: Path) -> None:
    """Banking privacy: by default the prompt text is SHA-256'd."""
    from kryon.learning.selection_telemetry import log_selection

    log_selection(
        user_msg="auditá el fortigate de BancoSecreto",
        ranking_mode="hybrid",
        candidates=[],
        selected=[],
    )
    record = json.loads(log_dir.read_text(encoding="utf-8").strip())
    assert "user_msg" not in record
    assert "BancoSecreto" not in json.dumps(record)
    # The hash field is present and looks like sha256 hex.
    h = record["user_msg_hash"]
    assert isinstance(h, str)
    assert len(h) == 64  # sha256 hex
    assert all(c in "0123456789abcdef" for c in h)


def test_plaintext_mode_includes_message_text(
    log_dir: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operator can opt in to plaintext logging for full auditability —
    only when explicitly enabled."""
    monkeypatch.setenv("KRYON_SELECTION_LOG_PLAINTEXT", "1")
    from kryon.learning.selection_telemetry import log_selection

    log_selection(
        user_msg="full message text",
        ranking_mode="priority",
        candidates=[],
        selected=[],
    )
    record = json.loads(log_dir.read_text(encoding="utf-8").strip())
    assert record["user_msg"] == "full message text"
    # The hash is still there for cross-correlation.
    assert "user_msg_hash" in record


# ---------- Disable ----------


def test_disable_flag_skips_writes(
    log_dir: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRYON_SELECTION_LOG_DISABLE", "1")
    from kryon.learning.selection_telemetry import log_selection

    log_selection(user_msg="x", ranking_mode="priority", candidates=[], selected=[])
    # File never created.
    assert not log_dir.exists()


# ---------- Schema ----------


def test_record_has_iso_timestamp(log_dir: Path) -> None:
    from datetime import datetime

    from kryon.learning.selection_telemetry import log_selection

    log_selection(user_msg="x", ranking_mode="priority", candidates=[], selected=[])
    record = json.loads(log_dir.read_text(encoding="utf-8").strip())
    # parseable as ISO 8601
    datetime.fromisoformat(record["ts"])


def test_record_includes_kryon_version_when_available(log_dir: Path) -> None:
    """Provenance: tie each log line to the Kryon version that produced it."""
    from kryon.learning.selection_telemetry import log_selection

    log_selection(user_msg="x", ranking_mode="priority", candidates=[], selected=[])
    record = json.loads(log_dir.read_text(encoding="utf-8").strip())
    # version field is present (may be "unknown" if not packaged)
    assert "kryon_version" in record


# ---------- Resilience ----------


def test_log_failure_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disk full / permission denied / etc. must not bubble up — telemetry
    is best-effort and should never break a turn."""
    # Point at a path that's invalid on every OS.
    monkeypatch.setenv("KRYON_SELECTION_LOG", "/dev/null/cannot/write/here.jsonl")
    monkeypatch.delenv("KRYON_SELECTION_LOG_DISABLE", raising=False)

    from kryon.learning.selection_telemetry import log_selection

    # Must not raise.
    log_selection(user_msg="x", ranking_mode="priority", candidates=[], selected=[])


# ---------- Read API ----------


def test_read_recent_returns_newest_first(log_dir: Path) -> None:
    from kryon.learning.selection_telemetry import log_selection, read_recent

    for i in range(3):
        log_selection(
            user_msg=f"msg-{i}", ranking_mode="priority",
            candidates=[], selected=[f"skill-{i}"],
        )

    rows = read_recent(limit=2)
    assert len(rows) == 2
    # newest first
    assert rows[0]["selected"] == ["skill-2"]
    assert rows[1]["selected"] == ["skill-1"]


def test_read_recent_handles_missing_log() -> None:
    """No log yet — read_recent returns []."""
    from kryon.learning.selection_telemetry import read_recent

    # Don't override env — points at default ~/.kryon/selection_log.jsonl
    # which may not exist on the test runner. Use a guaranteed-missing path.
    import os, tempfile

    with tempfile.TemporaryDirectory() as td:
        os.environ["KRYON_SELECTION_LOG"] = str(Path(td) / "ghost.jsonl")
        try:
            assert read_recent(limit=10) == []
        finally:
            del os.environ["KRYON_SELECTION_LOG"]
