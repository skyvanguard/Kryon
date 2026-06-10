"""F3.3 — Historical trending for the executive summary.

A single report is a snapshot; clients want the trajectory ("are we getting
better?"). This records each engagement's severity counts to a per-client trend
log and computes the trend (deltas, direction, per-severity series) for the
executive section. Pure + filesystem only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class TrendPoint:
    date: str
    total: int
    by_severity: dict[str, int]


def _trend_path(client: str, base_dir: Path | None) -> Path:
    base = Path(base_dir) if base_dir else (Path.home() / ".kryon" / "trends")
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in (client or "client").lower())[:40]
    return base / f"{slug or 'client'}.jsonl"


def record_trend_point(client: str, date: str, by_severity: dict[str, int], base_dir: Path | None = None) -> Path:
    """Append one engagement's severity counts to the client's trend log."""
    path = _trend_path(client, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    total = sum(int(v) for v in by_severity.values())
    row = {"date": date, "total": total, "by_severity": {k: int(v) for k, v in by_severity.items()}}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def load_trend(client: str, base_dir: Path | None = None) -> list[TrendPoint]:
    path = _trend_path(client, base_dir)
    if not path.exists():
        return []
    points: list[TrendPoint] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        points.append(
            TrendPoint(date=d.get("date", ""), total=int(d.get("total", 0)), by_severity=d.get("by_severity", {}))
        )
    return points


def _crit_high(point: TrendPoint) -> int:
    return int(point.by_severity.get("CRITICAL", 0)) + int(point.by_severity.get("HIGH", 0))


def build_trend(points: list[TrendPoint]) -> dict:
    """Series + latest deltas + direction (by critical+high movement)."""
    if not points:
        return {"points": [], "direction": "n/a"}
    latest = points[-1]
    prev = points[-2] if len(points) >= 2 else None
    delta_total = latest.total - prev.total if prev else 0
    delta_ch = _crit_high(latest) - _crit_high(prev) if prev else 0
    if prev is None:
        direction = "baseline"
    elif delta_ch < 0:
        direction = "improving"
    elif delta_ch > 0:
        direction = "worsening"
    else:
        direction = "stable"
    series = {sev: [int(p.by_severity.get(sev, 0)) for p in points] for sev in _SEVERITY_ORDER}
    return {
        "points": [{"date": p.date, "total": p.total, "by_severity": p.by_severity} for p in points],
        "latest": {"date": latest.date, "total": latest.total, "critical_high": _crit_high(latest)},
        "delta_total": delta_total,
        "delta_critical_high": delta_ch,
        "direction": direction,
        "series": series,
        "runs": len(points),
    }


def format_trend_markdown(trend: dict) -> str:
    """Executive-summary trend section."""
    if not trend.get("points"):
        return ""
    arrow = {"improving": "↓ improving", "worsening": "↑ worsening", "stable": "→ stable", "baseline": "• baseline"}
    direction = arrow.get(trend["direction"], trend["direction"])
    lines = [
        "## Trend",
        "",
        f"- Runs tracked: **{trend['runs']}**",
        f"- Latest total findings: **{trend['latest']['total']}** (Δ {trend['delta_total']:+d} vs previous)",
        f"- Critical+High: **{trend['latest']['critical_high']}** (Δ {trend['delta_critical_high']:+d}) — {direction}",
    ]
    return "\n".join(lines)
