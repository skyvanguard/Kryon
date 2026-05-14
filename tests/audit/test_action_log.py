"""F119 — Append-only JSONL action log tests.

Forensic baseline: every tool call by the agent lands as one JSONL
line so post-engagement we can answer "what did Kryon do, when, and
with what input/output". Args and results pass through the PAN
redactor before being persisted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryon.audit.action_log import ActionLog, ActionLogEntry


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


# ---------------------------------------------------------------------------
# Schema + persistence
# ---------------------------------------------------------------------------


def test_append_writes_single_jsonl_line(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-001")
    log.append(tool_name="nmap", args={"target": "1.2.3.4"}, result="open 22/tcp", phase="recon")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool_name"] == "nmap"
    assert entry["engagement_id"] == "eng-001"
    assert entry["phase"] == "recon"
    assert "timestamp" in entry
    assert "args_hash" in entry
    assert "result_hash" in entry


def test_append_writes_multiple_entries(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-002")
    log.append(tool_name="nmap", args={}, result="x", phase="recon")
    log.append(tool_name="curl", args={}, result="y", phase="recon")
    log.append(tool_name="report", args={}, result="z", phase="reporting")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    tools = [json.loads(line)["tool_name"] for line in lines]
    assert tools == ["nmap", "curl", "report"]


def test_args_hash_is_deterministic_sha256(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-003")
    log.append(tool_name="t", args={"a": 1, "b": 2}, result="r", phase="p")
    log.append(tool_name="t", args={"a": 1, "b": 2}, result="r", phase="p")

    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["args_hash"] == lines[1]["args_hash"]
    assert len(lines[0]["args_hash"]) == 64  # hex sha256


def test_different_args_produce_different_hashes(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-004")
    log.append(tool_name="t", args={"target": "a"}, result="r", phase="p")
    log.append(tool_name="t", args={"target": "b"}, result="r", phase="p")

    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["args_hash"] != lines[1]["args_hash"]


def test_duration_and_status_persisted(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-005")
    log.append(tool_name="t", args={}, result="r", phase="p", duration_ms=1234, status="ok")

    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["duration_ms"] == 1234
    assert entry["status"] == "ok"


# ---------------------------------------------------------------------------
# Redaction integration
# ---------------------------------------------------------------------------


def test_pan_in_args_is_redacted_in_persisted_entry(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-006")
    log.append(
        tool_name="probe",
        args={"body": "card 4242424242424242 charge"},
        result="ok",
        phase="exploitation",
    )

    raw = log_path.read_text(encoding="utf-8")
    assert "4242424242424242" not in raw
    assert "[PAN-REDACTED]" in raw or "**" in raw


def test_pan_in_result_is_redacted(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-007")
    log.append(
        tool_name="probe",
        args={},
        result="response body: pan=4242424242424242 ok",
        phase="exploitation",
    )

    raw = log_path.read_text(encoding="utf-8")
    assert "4242424242424242" not in raw


def test_redaction_counts_are_persisted(log_path):
    log = ActionLog(path=log_path, engagement_id="eng-008")
    log.append(
        tool_name="probe",
        args={"a": "card 4242424242424242"},
        result="card 5555 5555 5555 4444",
        phase="x",
    )

    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry.get("redaction_count", 0) >= 2


# ---------------------------------------------------------------------------
# Append-only semantics + env toggle
# ---------------------------------------------------------------------------


def test_append_only_does_not_overwrite_existing(log_path):
    log_path.write_text('{"prior":"entry"}\n', encoding="utf-8")
    log = ActionLog(path=log_path, engagement_id="eng-009")
    log.append(tool_name="t", args={}, result="r", phase="p")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert lines[0] == '{"prior":"entry"}'


def test_audit_disabled_via_env_skips_write(log_path, monkeypatch):
    monkeypatch.setenv("KRYON_AUDIT_LOG_ENABLED", "false")
    log = ActionLog(path=log_path, engagement_id="eng-010")
    log.append(tool_name="t", args={}, result="r", phase="p")

    # File should not be created when disabled.
    assert not log_path.exists() or log_path.read_text(encoding="utf-8") == ""


def test_log_path_parent_directory_created(tmp_path):
    nested = tmp_path / "nested" / "deep" / "audit.jsonl"
    log = ActionLog(path=nested, engagement_id="eng-011")
    log.append(tool_name="t", args={}, result="r", phase="p")

    assert nested.exists()
    assert nested.parent.is_dir()


# ---------------------------------------------------------------------------
# ActionLogEntry dataclass shape
# ---------------------------------------------------------------------------


def test_entry_to_dict_contains_required_fields():
    e = ActionLogEntry(
        timestamp="2026-05-14T12:00:00Z",
        engagement_id="x",
        phase="recon",
        tool_name="nmap",
        args_hash="a" * 64,
        args_redacted="{}",
        result_hash="b" * 64,
        result_redacted="x",
        duration_ms=0,
        status="ok",
        redaction_count=0,
    )
    d = e.to_dict()
    for key in (
        "timestamp",
        "engagement_id",
        "phase",
        "tool_name",
        "args_hash",
        "args_redacted",
        "result_hash",
        "result_redacted",
        "duration_ms",
        "status",
        "redaction_count",
    ):
        assert key in d
