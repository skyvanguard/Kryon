"""F194 — Engagement → learning signal wire tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from kryon.learning.engagement_signal import (
    _map_verdict_to_outcome,
    _serialize_finding,
    emit_engagement_learning_signal,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_drafts(monkeypatch, tmp_path):
    """Each test gets a fresh tmp drafts dir so the synthesizer doesn't
    persist drafts to the real ~/.kryon/drafts/."""
    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(drafts_dir))
    return drafts_dir


# ---------------------------------------------------------------------------
# Verdict mapping
# ---------------------------------------------------------------------------


def test_verdict_satisfied_to_success():
    assert _map_verdict_to_outcome("satisfied") == "success"


def test_verdict_partial_to_partial():
    assert _map_verdict_to_outcome("partial") == "partial"


def test_verdict_not_met_to_recon_only():
    """``NOT_MET`` is still worth a draft if it surfaced recon evidence."""
    assert _map_verdict_to_outcome("not_met") == "recon-only"


def test_verdict_unknown_to_fail():
    assert _map_verdict_to_outcome("error") == "fail"
    assert _map_verdict_to_outcome("") == "fail"
    assert _map_verdict_to_outcome(None) == "fail"  # type: ignore[arg-type]


def test_verdict_case_insensitive():
    assert _map_verdict_to_outcome("SATISFIED") == "success"
    assert _map_verdict_to_outcome("Partial") == "partial"


# ---------------------------------------------------------------------------
# Finding serialization
# ---------------------------------------------------------------------------


def test_finding_dict_passes_through():
    f = {"cwe": "CWE-89", "severity": "HIGH", "rule_id": "SQLI-X", "message": "..."}
    out = _serialize_finding(f)
    assert out["cwe"] == "CWE-89"
    assert out["severity"] == "HIGH"


def test_finding_dataclass_serialized():
    """Finding dataclass instances → dict shape."""
    f = SimpleNamespace(
        cwe="CWE-79",
        severity="HIGH",
        rule_id="XSS-Reflected",
        message="reflected payload in /search?q=",
    )
    out = _serialize_finding(f)
    assert out["cwe"] == "CWE-79"
    assert out["rule_id"] == "XSS-Reflected"


def test_finding_message_truncated_to_200():
    f = {"cwe": "CWE-0", "severity": "LOW", "message": "x" * 500}
    out = _serialize_finding(f)
    assert len(out["message"]) <= 200


# ---------------------------------------------------------------------------
# emit_engagement_learning_signal — full flow
# ---------------------------------------------------------------------------


def _audit_path(tmp_path: Path) -> Path:
    """Make a synthetic audit JSONL file with 4 tool calls."""
    path = tmp_path / "audit.jsonl"
    entries = [
        {"tool_name": "whatweb_scan", "args_redacted": '{"target":"http://juice_shop:3000"}', "status": "ok"},
        {"tool_name": "nuclei_scan", "args_redacted": '{"target":"http://juice_shop:3000"}', "status": "ok"},
        {"tool_name": "nikto", "args_redacted": '{"host":"juice_shop"}', "status": "ok"},
        {"tool_name": "sqlmap", "args_redacted": '{"url":"/rest/user/login"}', "status": "vulnerable"},
    ]
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    return path


def test_satisfied_engagement_produces_draft(tmp_path, _isolated_drafts):
    audit_path = _audit_path(tmp_path)
    findings = [
        {"cwe": "CWE-89", "severity": "HIGH", "rule_id": "SQLI-X", "message": "SQLi"},
        {"cwe": "CWE-200", "severity": "HIGH", "rule_id": "EXPOSED", "message": "info disclosure"},
    ]
    verdict_info = {
        "verdict": "satisfied",
        "reasoning": "1 high SQLi finding confirmed",
        "goal_kind": "vuln_search",
        "goal_raw": "find SQLi or XSS",
    }
    draft = emit_engagement_learning_signal(
        target="http://juice_shop:3000",
        verdict_info=verdict_info,
        findings=findings,
        families=["node.js", "express"],
        audit_log_path=audit_path,
        engagement_id="test-eng-1",
    )
    assert draft is not None
    assert Path(draft).exists()
    body = Path(draft).read_text(encoding="utf-8")
    assert "node.js" in body or "express" in body
    assert "sqlmap" in body or "nuclei" in body


def test_fail_outcome_no_draft(tmp_path, _isolated_drafts):
    audit_path = _audit_path(tmp_path)
    draft = emit_engagement_learning_signal(
        target="http://x",
        verdict_info={"verdict": "error", "reasoning": "..."},
        findings=[],
        families=[],
        audit_log_path=audit_path,
        engagement_id="test-fail",
    )
    assert draft is None


def test_thin_chain_no_draft(tmp_path, _isolated_drafts):
    """Synthesizer requires chain_len >= 2; thinner gets rejected."""
    short_audit = tmp_path / "audit.jsonl"
    short_audit.write_text(
        json.dumps({"tool_name": "whatweb_scan", "args_redacted": "{}", "status": "ok"}),
        encoding="utf-8",
    )
    draft = emit_engagement_learning_signal(
        target="http://x",
        verdict_info={"verdict": "satisfied"},
        findings=[{"cwe": "CWE-0", "severity": "LOW", "rule_id": "x"}],
        families=["nginx"],
        audit_log_path=short_audit,
        engagement_id="thin",
    )
    assert draft is None


def test_missing_audit_log_no_draft(tmp_path, _isolated_drafts):
    """No audit log file → no chain → no draft."""
    draft = emit_engagement_learning_signal(
        target="http://x",
        verdict_info={"verdict": "satisfied"},
        findings=[{"cwe": "CWE-0"}],
        families=["nginx"],
        audit_log_path=tmp_path / "does-not-exist.jsonl",
        engagement_id="no-audit",
    )
    assert draft is None


def test_partial_verdict_produces_draft(tmp_path, _isolated_drafts):
    """``partial`` is the synthesizer's default min threshold; PARTIAL
    engagements should produce drafts so we capture half-results too."""
    audit_path = _audit_path(tmp_path)
    draft = emit_engagement_learning_signal(
        target="http://x",
        verdict_info={"verdict": "partial", "reasoning": "1 medium finding"},
        findings=[{"cwe": "CWE-200", "severity": "MEDIUM", "rule_id": "x"}],
        families=["nginx"],
        audit_log_path=audit_path,
        engagement_id="test-partial",
    )
    assert draft is not None


# ---------------------------------------------------------------------------
# Best-effort: no exceptions escape
# ---------------------------------------------------------------------------


def test_emit_never_raises_on_garbage_input(tmp_path, _isolated_drafts):
    """Function is best-effort — wrap everything in try/except so the
    engagement never crashes because of a learning side-effect."""
    draft = emit_engagement_learning_signal(
        target=None,  # type: ignore[arg-type]
        verdict_info=None,
        findings=None,  # type: ignore[arg-type]
        families=None,  # type: ignore[arg-type]
        audit_log_path=None,  # type: ignore[arg-type]
        engagement_id=None,  # type: ignore[arg-type]
    )
    assert draft is None
