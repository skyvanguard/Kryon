"""Report section — finding trend analysis."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from kryon.reporting.charts import generate_trend_chart_svg


def render_trend_analysis(findings: list, store=None) -> str:
    """Render finding trend chart section for reports."""
    if not findings:
        return '<div class="section"><h2>Trend Analysis</h2><p>No findings to analyze.</p></div>'

    # Group findings by week
    weekly: dict[str, int] = defaultdict(int)
    for f in findings:
        try:
            if isinstance(f, dict):
                first_seen = f.get("first_seen", "")
            else:
                first_seen = getattr(f, "first_seen", "") or ""
            if first_seen:
                dt = datetime.fromisoformat(str(first_seen))
                week = dt.strftime("%Y-W%W")
                weekly[week] += 1
        except (ValueError, TypeError):
            continue

    data_points = [{"label": k, "value": v} for k, v in sorted(weekly.items())]
    chart_svg = generate_trend_chart_svg(data_points)

    return f"""<div class="section">
<h2>Trend Analysis</h2>
<p>Finding discovery rate over {len(data_points)} weeks.</p>
{chart_svg}
</div>"""
