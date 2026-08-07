"""F141 — Executive digest tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from kryon.notifications.exec_digest import (
    ExecDigest,
    build_digest,
    render_digest,
    render_markdown,
    render_slack,
)


def _write_audit(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def _entry(
    ts: str, eng: str, phase: str, tool: str, status: str = "ok", duration_ms: int = 100, redact: int = 0
) -> dict:
    return {
        "timestamp": ts,
        "engagement_id": eng,
        "phase": phase,
        "tool_name": tool,
        "args_hash": "a" * 64,
        "args_redacted": "{}",
        "result_hash": "b" * 64,
        "result_redacted": "",
        "duration_ms": duration_ms,
        "status": status,
        "redaction_count": redact,
    }


# ---------------------------------------------------------------------------
# build_digest
# ---------------------------------------------------------------------------


def test_empty_audit_dir_returns_zero_digest(tmp_path):
    digest = build_digest(audit_dir=tmp_path)
    assert digest.engagements == 0
    assert digest.tool_calls == 0
    assert digest.failed_phases == 0


def test_aggregates_across_engagements(tmp_path):
    _write_audit(
        tmp_path / "A.jsonl",
        [
            _entry("2026-05-10T10:00:00Z", "A", "recon", "nmap"),
            _entry("2026-05-10T10:01:00Z", "A", "vuln_scan", "nuclei", status="failed"),
        ],
    )
    _write_audit(tmp_path / "B.jsonl", [_entry("2026-05-11T10:00:00Z", "B", "recon", "nmap")])

    digest = build_digest(audit_dir=tmp_path)

    assert digest.engagements == 2
    assert digest.tool_calls == 3
    assert digest.failed_phases == 1


def test_top_tools_limited_by_top_n(tmp_path):
    entries = []
    for i in range(5):
        entries.append(_entry(f"2026-05-10T10:00:0{i}Z", "X", "r", "nmap"))
    for i in range(3):
        entries.append(_entry(f"2026-05-10T10:01:0{i}Z", "X", "r", "nuclei"))
    _write_audit(tmp_path / "X.jsonl", entries)

    digest = build_digest(audit_dir=tmp_path, top_n=1)
    assert len(digest.top_tools) == 1
    assert digest.top_tools[0] == ("nmap", 5)


def test_window_filter_applied(tmp_path):
    _write_audit(
        tmp_path / "X.jsonl",
        [
            _entry("2026-05-01T10:00:00Z", "old", "r", "nmap"),
            _entry("2026-05-10T10:00:00Z", "new", "r", "nmap"),
        ],
    )
    digest = build_digest(
        audit_dir=tmp_path,
        since=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    assert digest.tool_calls == 1
    assert digest.engagements == 1


def test_redaction_totals_summed(tmp_path):
    _write_audit(
        tmp_path / "X.jsonl",
        [
            _entry("2026-05-10T10:00:00Z", "x", "r", "t", redact=2),
            _entry("2026-05-10T10:01:00Z", "x", "r", "t", redact=3),
        ],
    )
    digest = build_digest(audit_dir=tmp_path)
    assert digest.total_redactions == 5


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _sample_digest() -> ExecDigest:
    return ExecDigest(
        window_start="2026-05-01T00:00:00Z",
        window_end="2026-05-15T00:00:00Z",
        engagements=3,
        tool_calls=42,
        failed_phases=1,
        total_redactions=7,
        top_tools=[("nmap", 10), ("nuclei", 5)],
        avg_duration_per_phase={"recon": 1000, "vuln_scan": 5000},
        engagement_ids=["eng-A", "eng-B", "eng-C"],
    )


def test_render_markdown_contains_headings():
    text = render_markdown(_sample_digest())
    assert "# Kryon Executive Digest" in text
    assert "Engagements" in text
    assert "nmap" in text
    assert "eng-A" in text


def test_render_slack_uses_mrkdwn():
    text = render_slack(_sample_digest())
    assert "*Kryon Executive Digest*" in text
    assert "nmap" in text


def test_render_dispatcher_picks_format():
    assert "# Kryon" in render_digest(_sample_digest(), fmt="markdown")
    assert "*Kryon" in render_digest(_sample_digest(), fmt="slack")
    assert '"engagements": 3' in render_digest(_sample_digest(), fmt="json")


def test_render_dispatcher_unknown_format_defaults_to_markdown():
    assert "# Kryon" in render_digest(_sample_digest(), fmt="unknown-format-x")


def test_digest_to_dict_is_json_serializable():
    d = _sample_digest()
    serialized = json.dumps(d.to_dict())
    parsed = json.loads(serialized)
    assert parsed["engagements"] == 3
    assert parsed["top_tools"][0] == ["nmap", 10]
