"""SVG chart generators for reports — gauge, pie, trend, bar."""

from __future__ import annotations

import math


def generate_risk_gauge_svg(score: float, width: int = 300, height: int = 180) -> str:
    """Generate a semicircle risk gauge SVG."""
    cx, cy = width // 2, height - 20
    radius = min(cx, cy) - 20
    # Score mapped to angle (0-180 degrees)
    angle = max(0, min(score / 100 * 180, 180))
    rad = math.radians(180 - angle)
    needle_x = cx + radius * 0.8 * math.cos(rad)
    needle_y = cy - radius * 0.8 * math.sin(rad)

    # Color based on score
    if score >= 75:
        color = "#FF0000"
        label = "Critical"
    elif score >= 50:
        color = "#FF6600"
        label = "High"
    elif score >= 25:
        color = "#FFCC00"
        label = "Medium"
    else:
        color = "#00CC00"
        label = "Low"

    return f"""<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#00CC00"/>
      <stop offset="33%" style="stop-color:#FFCC00"/>
      <stop offset="66%" style="stop-color:#FF6600"/>
      <stop offset="100%" style="stop-color:#FF0000"/>
    </linearGradient>
  </defs>
  <path d="M {cx - radius} {cy} A {radius} {radius} 0 0 1 {cx + radius} {cy}"
        fill="none" stroke="url(#gaugeGrad)" stroke-width="20" stroke-linecap="round"/>
  <line x1="{cx}" y1="{cy}" x2="{needle_x}" y2="{needle_y}"
        stroke="{color}" stroke-width="3" stroke-linecap="round"/>
  <circle cx="{cx}" cy="{cy}" r="6" fill="{color}"/>
  <text x="{cx}" y="{cy + 25}" text-anchor="middle" font-size="18" font-weight="bold" fill="{color}">{score:.0f}</text>
  <text x="{cx}" y="{cy + 42}" text-anchor="middle" font-size="12" fill="#666">{label} Risk</text>
</svg>"""


def generate_severity_pie_svg(distribution: dict[str, int], size: int = 200) -> str:
    """Generate a donut chart SVG for severity distribution."""
    total = sum(distribution.values())
    if total == 0:
        return f'<svg viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg"><text x="{size // 2}" y="{size // 2}" text-anchor="middle" fill="#666">No data</text></svg>'

    colors = {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFCC00", "low": "#00CC00", "info": "#0066FF"}
    cx, cy, r = size // 2, size // 2, size // 2 - 20
    inner_r = r * 0.6
    start_angle = 0
    paths = []

    for severity, count in distribution.items():
        if count == 0:
            continue
        sweep = count / total * 360
        end_angle = start_angle + sweep
        large_arc = 1 if sweep > 180 else 0
        color = colors.get(severity, "#999")

        sr, er = math.radians(start_angle - 90), math.radians(end_angle - 90)
        x1_o, y1_o = cx + r * math.cos(sr), cy + r * math.sin(sr)
        x2_o, y2_o = cx + r * math.cos(er), cy + r * math.sin(er)
        x1_i, y1_i = cx + inner_r * math.cos(er), cy + inner_r * math.sin(er)
        x2_i, y2_i = cx + inner_r * math.cos(sr), cy + inner_r * math.sin(sr)

        path = f"M {x1_o} {y1_o} A {r} {r} 0 {large_arc} 1 {x2_o} {y2_o} L {x1_i} {y1_i} A {inner_r} {inner_r} 0 {large_arc} 0 {x2_i} {y2_i} Z"
        paths.append(f'<path d="{path}" fill="{color}" opacity="0.9"/>')
        start_angle = end_angle

    paths_str = "\n  ".join(paths)
    # Center text
    center_text = (
        f'<text x="{cx}" y="{cy}" text-anchor="middle" font-size="20" font-weight="bold" fill="#333">{total}</text>'
    )
    center_label = f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="10" fill="#666">findings</text>'

    return f"""<svg viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
  {paths_str}
  {center_text}
  {center_label}
</svg>"""


def generate_trend_chart_svg(data_points: list[dict], width: int = 500, height: int = 200) -> str:
    """Generate a line chart SVG for risk trend over time."""
    if not data_points:
        return f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg"><text x="{width // 2}" y="{height // 2}" text-anchor="middle" fill="#666">No trend data</text></svg>'

    padding = 40
    chart_w = width - 2 * padding
    chart_h = height - 2 * padding
    values = [p.get("value", p.get("finding_count", 0)) for p in data_points]
    max_val = max(values) if values else 1
    if max_val == 0:
        max_val = 1

    points = []
    for i, val in enumerate(values):
        x = padding + (i / max(len(values) - 1, 1)) * chart_w
        y = padding + chart_h - (val / max_val * chart_h)
        points.append(f"{x},{y}")

    polyline = " ".join(points)
    # Fill area
    area_points = f"{padding},{padding + chart_h} {polyline} {padding + chart_w},{padding + chart_h}"

    return f"""<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
  <rect x="{padding}" y="{padding}" width="{chart_w}" height="{chart_h}" fill="#f8f9fa" rx="4"/>
  <polygon points="{area_points}" fill="#00d4ff" opacity="0.1"/>
  <polyline points="{polyline}" fill="none" stroke="#00d4ff" stroke-width="2"/>
  <text x="{padding}" y="{padding - 8}" font-size="12" fill="#666">Risk Trend</text>
</svg>"""


def generate_remediation_status_svg(stats: dict, width: int = 400, height: int = 120) -> str:
    """Generate horizontal bar chart for remediation status."""
    statuses = ["open", "remediated", "accepted", "false_positive"]
    colors = {"open": "#FF0000", "remediated": "#00CC00", "accepted": "#FFCC00", "false_positive": "#999"}
    total = sum(stats.get(s, 0) for s in statuses)
    if total == 0:
        total = 1

    bar_height = 20
    y_offset = 15
    bars = []
    for i, status in enumerate(statuses):
        count = stats.get(status, 0)
        bar_w = max(count / total * (width - 120), 2)
        y = y_offset + i * (bar_height + 8)
        color = colors.get(status, "#999")
        bars.append(f'<text x="0" y="{y + 14}" font-size="11" fill="#333">{status}</text>')
        bars.append(f'<rect x="100" y="{y}" width="{bar_w}" height="{bar_height}" fill="{color}" rx="3"/>')
        bars.append(f'<text x="{105 + bar_w}" y="{y + 14}" font-size="11" fill="#666">{count}</text>')

    bars_str = "\n  ".join(bars)
    return f"""<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
  {bars_str}
</svg>"""
