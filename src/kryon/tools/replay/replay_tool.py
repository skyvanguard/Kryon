"""F113 — agent-facing tool wrapper for the replay engine."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.auth.runner import (
    AuthFlowConfig,
    AuthSuccessSignal,
    LoginCredentials,
)
from kryon.tools.pipeline.pipeline import UnifiedFinding
from kryon.tools.replay.engine import (
    ReplayConfig,
    ReplayResult,
    ReplayedFinding,
    run_replay,
)

__all__ = ["replay_findings"]


def _replayed_to_dict(r: ReplayedFinding) -> dict[str, Any]:
    return {
        "rule_id": r.original.rule_id,
        "source_module": r.original.source_module,
        "severity": r.original.severity,
        "title": r.original.title,
        "target": r.original.target,
        "status": r.status,
        "detail": r.detail,
        "new_severity": r.new_severity,
        "new_title": r.new_title,
        "elapsed_seconds": round(r.elapsed_seconds, 3),
    }


def _result_to_dict(r: ReplayResult) -> dict[str, Any]:
    return {
        "elapsed_seconds": round(r.elapsed_seconds, 3),
        "summary": {
            "total": len(r.replayed),
            "still_present": r.still_present_count,
            "disappeared": r.disappeared_count,
            "changed": r.changed_count,
            "inconclusive": r.inconclusive_count,
        },
        "auth_success": bool(r.auth_session and r.auth_session.success),
        "replayed": [_replayed_to_dict(rf) for rf in r.replayed],
    }


def _parse_findings(raw: list) -> list[UnifiedFinding]:
    findings: list[UnifiedFinding] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        findings.append(
            UnifiedFinding(
                rule_id=str(entry.get("rule_id") or ""),
                severity=str(entry.get("severity") or "INFO"),
                title=str(entry.get("title") or ""),
                detail=str(entry.get("detail") or ""),
                remediation=str(entry.get("remediation") or ""),
                source_module=str(entry.get("source_module") or ""),
                target=str(entry.get("target") or ""),
                extra=tuple(
                    (str(k), str(v))
                    for k, v in (entry.get("extra") or {}).items()
                ),
            )
        )
    return findings


def _parse_auth_flow(doc: dict) -> AuthFlowConfig | None:
    if not isinstance(doc, dict):
        return None
    if not doc.get("login_url"):
        return None
    creds = LoginCredentials(
        username=str(doc.get("username") or ""),
        password=str(doc.get("password") or ""),
        username_field=str(doc.get("username_field") or "username"),
        password_field=str(doc.get("password_field") or "password"),
    )
    sig_doc = doc.get("success_signal") or {}
    if not isinstance(sig_doc, dict):
        sig_doc = {}
    sig = AuthSuccessSignal(
        expected_status=(
            int(sig_doc["expected_status"])
            if sig_doc.get("expected_status") is not None
            else None
        ),
        expected_cookie_name=str(sig_doc.get("expected_cookie_name") or ""),
        expected_body_substring=str(sig_doc.get("expected_body_substring") or ""),
        expected_redirect_path=str(sig_doc.get("expected_redirect_path") or ""),
        expected_jwt_in_body=bool(sig_doc.get("expected_jwt_in_body", False)),
    )
    return AuthFlowConfig(
        login_url=str(doc["login_url"]),
        credentials=creds,
        success_signal=sig,
    )


@function_tool
def replay_findings(config_json: str) -> str:
    """Re-verify a list of prior UnifiedFindings against the target.

    Args:
        config_json: JSON object with:
          - findings: [{rule_id, severity, title, source_module,
                        target, detail, remediation, extra}]
          - auth_flow (optional): {login_url, username, password,
                                   ...same shape as F111}
          - timeout_seconds (default 8)
          - rate_limit_per_second (default 5)

    Returns:
        JSON summary classifying each finding as still-present /
        disappeared / changed / inconclusive.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})

    raw_findings = doc.get("findings")
    if not isinstance(raw_findings, list):
        return json.dumps({"error": "findings: list[obj] required"})
    findings = tuple(_parse_findings(raw_findings))
    if not findings:
        return json.dumps({"error": "no parseable findings supplied"})

    auth = _parse_auth_flow(doc.get("auth_flow") or {})
    cfg = ReplayConfig(
        findings=findings,
        auth_flow=auth,
        timeout_seconds=float(doc.get("timeout_seconds") or 8.0),
        rate_limit_per_second=float(doc.get("rate_limit_per_second") or 5.0),
        user_agent=str(doc.get("user_agent") or "Kryon-Replay/1.0 (banca-safe; +read-only)"),
        follow_redirects=bool(doc.get("follow_redirects", True)),
    )
    result = run_replay(cfg)
    return json.dumps(_result_to_dict(result), ensure_ascii=False)
