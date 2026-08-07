"""F1.3 — Retest delta reporting.

engage already diffs each run against the saved baseline (F133). This turns that
diff into a client-facing DELTA deliverable: a structured remediation report
(what got fixed, what's still open, what's newly introduced, % progress) plus an
action spreadsheet of the NEW + CHANGED findings. Pure orchestration over
baseline_diff + findings_export — the CLI command handles re-running engage.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from kryon.state.baseline_diff import compute_diff


def build_delta_report(previous: list[Any] | None, current: list[Any]) -> dict:
    """Diff two runs and add a remediation-progress block on top."""
    diff = compute_diff(previous, current)
    baseline_total = len(diff.gone) + len(diff.stable) + len(diff.changed)
    remediated = len(diff.gone)
    progress = round(100 * remediated / baseline_total, 1) if baseline_total else 0.0
    report = diff.to_dict()
    report["remediation"] = {
        "baseline_total": baseline_total,
        "remediated": remediated,
        "still_open": len(diff.stable) + len(diff.changed),
        "newly_introduced": len(diff.new),
        "progress_pct": progress,
    }
    return report


def format_delta_summary(report: dict) -> str:
    """One-line operator summary, e.g. 'retest: 5/8 remediated (62.5%) …'."""
    r = report["remediation"]
    return (
        f"retest: {r['remediated']}/{r['baseline_total']} remediated "
        f"({r['progress_pct']}%), {r['still_open']} still open, "
        f"{r['newly_introduced']} newly introduced"
    )


def _action_rows(report: dict):
    """NEW + CHANGED (current side) findings — the actionable delta — as rows."""
    from kryon.reporting.findings_export import from_engage_finding

    actionable: list[dict] = list(report.get("new", []))
    for ch in report.get("changed", []):
        if isinstance(ch, dict) and "current" in ch:
            actionable.append(ch["current"])
    return [from_engage_finding(SimpleNamespace(**f)) for f in actionable if isinstance(f, dict)]


def write_delta_report(
    report: dict,
    out_dir: Path,
    client_name: str = "",
    fmt: str = "xlsx",
) -> dict[str, object]:
    """Write delta.json + an action spreadsheet (NEW + CHANGED). Returns paths."""
    from kryon.reporting.findings_export import export_findings

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    delta_path = out_dir / "retest-delta.json"
    delta_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    rows = _action_rows(report)
    try:
        sheet = export_findings(rows, fmt=fmt, client_name=client_name or "retest", report_type="retest-actions")
    except RuntimeError:
        sheet = export_findings(rows, fmt="csv", client_name=client_name or "retest", report_type="retest-actions")
    return {"delta_json": delta_path, "action_sheet": sheet, "report": report}
