"""F88 — agent-facing tool wrapper for the retester.

Two operation shapes:
  - Single replay: agent passes one RetestRecord JSON, gets one
    RetestVerdict + comparator metadata back.
  - Batch replay: agent passes a JSON array of records, gets the
    aggregated RetestReport.

Both modes obey the F88 banca-safety contract:
KRYON_RETEST_FIRE=true env AND fire=True kwarg for live HTTP;
GET-only unless KRYON_RETEST_ALLOW_MUTATIONS=true.
"""

from __future__ import annotations

import json
from typing import Any

from kryon.retester.aggregator import aggregate_retest
from kryon.retester.comparator import RetestVerdict
from kryon.retester.record import record_from_dict
from kryon.retester.replay import replay_finding
from kryon.sdk.agents import function_tool

__all__ = ["retest_finding"]


def _verdict_to_dict(v: RetestVerdict) -> dict[str, Any]:
    return {
        "verdict": v.verdict,
        "confidence": v.confidence,
        "reason": v.reason,
        "original_status": v.original_status,
        "current_status": v.current_status,
        "body_changed": v.body_changed,
        "status_changed": v.status_changed,
    }


def _summarize_report(report) -> dict[str, Any]:
    return {
        "total": report.total,
        "by_verdict": dict(report.by_verdict),
        "fix_rate": report.fix_rate,
        "still_open_count": len(report.still_open),
        "regressed_count": len(report.regressed),
        "still_open": [_verdict_to_dict(v) for v in report.still_open],
        "regressed": [_verdict_to_dict(v) for v in report.regressed],
    }


@function_tool
def retest_finding(
    records_json: str,
    fire: bool = False,
    auth_header_name: str = "Authorization",
    auth_header_value: str = "",
    timeout: int = 30,
) -> str:
    """Replay one or more findings and report verdicts.

    Args:
        records_json: A single RetestRecord JSON object OR a JSON
            array of records. The shape decides single vs batch mode.
        fire: required (with KRYON_RETEST_FIRE=true env) for live
            HTTP. Default False = dry-run; every verdict comes back
            with verdict='dry_run'.
        auth_header_name: header carrying the current auth token
            (default "Authorization").
        auth_header_value: the current token value WITHOUT prefix.
            For Bearer tokens the wrapper prepends "Bearer "
            automatically when the value lacks a space. Empty
            value = no auth injection (rare; only for unauthenticated
            replays).
        timeout: per-request timeout in seconds.

    Returns:
        JSON string. Single-record mode returns the verdict dict.
        Batch mode returns the RetestReport summary.
    """
    try:
        doc = json.loads(records_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})

    is_batch = isinstance(doc, list)
    raw_records = doc if is_batch else [doc] if isinstance(doc, dict) else None
    if raw_records is None:
        return json.dumps({"error": "records_json must be a JSON object or array of objects"})

    current_auth: dict[str, str] | None = None
    if auth_header_value.strip():
        # Bearer-prefix only if the value looks like a bare token (no
        # whitespace). "Basic xxx" / "Negotiate yyy" pass through.
        value = auth_header_value.strip()
        if " " not in value:
            value = f"Bearer {value}"
        current_auth = {auth_header_name: value}

    verdicts: list[RetestVerdict] = []
    for raw in raw_records:
        if not isinstance(raw, dict):
            continue
        record = record_from_dict(raw)
        verdict = replay_finding(
            record,
            current_auth=current_auth,
            fire=fire,
            timeout=timeout,
        )
        verdicts.append(verdict)

    if not is_batch:
        if not verdicts:
            return json.dumps({"error": "no record parsed from input"})
        return json.dumps(_verdict_to_dict(verdicts[0]), ensure_ascii=False)

    report = aggregate_retest(verdicts)
    return json.dumps(_summarize_report(report), ensure_ascii=False)
