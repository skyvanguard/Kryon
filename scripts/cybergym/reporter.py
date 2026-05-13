"""F86 — HTML scoreboard generator for CyberGym vuln-hunter v2.

Sibling of scripts/htb_bench/reporter.py — same self-contained
HTML/CSS aesthetic, no Jinja, no external CSS, ready for GitHub Pages.
Differences from the HTB reporter:

  - Metric vocabulary: detection_rate + wilson_lower_95 +
    false_positive_rate (no pwn/time-to-pwn).
  - Per-target verdict ladder:
        DETECT  — CWE matched AND file matched
        CWE     — CWE matched, file did not (partial credit)
        FILE    — file matched, CWE did not (partial credit)
        MISS    — neither matched
        ERR     — runner raised
  - Categories are CWE families, not platforms.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="kryon-bench F86 cybergym">
<title>{title}</title>
<style>
:root {{
  --bg: #0d1117; --fg: #e6edf3; --dim: #8b949e;
  --ok: #3fb950; --partial: #d29922; --fail: #f85149; --err: #d29922;
  --accent: #58a6ff; --border: #30363d;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 2rem; background: var(--bg); color: var(--fg);
        font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
header {{ max-width: 1100px; margin: 0 auto 2rem; }}
h1 {{ margin: 0 0 0.5rem; color: var(--accent); font-size: 1.6rem; }}
h2 {{ margin: 2rem 0 0.75rem; font-size: 1.15rem; }}
.subtitle {{ color: var(--dim); }}
main {{ max-width: 1100px; margin: 0 auto; }}
.kpi {{ display: flex; gap: 1.5rem; margin: 1.5rem 0; flex-wrap: wrap; }}
.kpi > div {{ background: #161b22; border: 1px solid var(--border);
              border-radius: 6px; padding: 1rem 1.25rem; min-width: 160px; }}
.kpi .label {{ color: var(--dim); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
.kpi .value {{ font-size: 1.6rem; font-weight: 600; margin-top: 0.25rem; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; }}
th, td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); text-align: left; }}
th {{ color: var(--dim); font-weight: 500; font-size: 0.8rem;
      text-transform: uppercase; letter-spacing: 0.05em; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.tag {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px;
        font-size: 0.75rem; font-weight: 600; }}
.tag.detect {{ background: rgba(63, 185, 80, 0.15); color: var(--ok); }}
.tag.partial {{ background: rgba(210, 153, 34, 0.15); color: var(--partial); }}
.tag.miss {{ background: rgba(248, 81, 73, 0.15); color: var(--fail); }}
.tag.err {{ background: rgba(210, 153, 34, 0.15); color: var(--err); }}
.bar {{ display: inline-block; height: 6px; vertical-align: middle;
        background: var(--ok); border-radius: 3px; }}
.bar.partial {{ background: var(--partial); }}
.bar.empty {{ background: var(--border); width: 80px; }}
footer {{ max-width: 1100px; margin: 3rem auto 1rem; color: var(--dim);
          font-size: 0.85rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
code {{ background: #161b22; padding: 0.1rem 0.35rem; border-radius: 3px;
        font-family: ui-monospace, monospace; font-size: 0.85em; }}
</style>
</head>
<body>
<header>
<h1>Kryon — CyberGym vuln-hunter scoreboard</h1>
<div class="subtitle">{subtitle}</div>
</header>
<main>
"""

_HTML_FOOT = """
</main>
<footer>
Reproduce: <code>python -m scripts.cybergym --all</code>.
Methodology: <a href="https://github.com/skyvanguard/Kryon/blob/main/docs/benchmarks/HOW_TO_REPRODUCE.md">HOW_TO_REPRODUCE.md</a>.
Wilson lower bound at 95% confidence — same statistic as
<code>src/kryon/learning/skill_scorer.py</code>.
</footer>
</body>
</html>
"""


def _bar_html(pct: float, width_px: int = 200) -> str:
    """Inline progress bar — green ≥0.5, amber 0<x<0.5, grey when 0."""
    if pct <= 0:
        return '<span class="bar empty"></span>'
    cls = "" if pct >= 0.5 else "partial"
    fill_px = max(2, int(width_px * pct))
    return f'<span class="bar {cls}" style="width:{fill_px}px"></span>'


def _verdict_tag(r: dict[str, Any]) -> str:
    if r.get("error"):
        return '<span class="tag err">ERR</span>'
    if r.get("detected"):
        return '<span class="tag detect">DETECT</span>'
    if r.get("cwe_match"):
        return '<span class="tag partial">CWE</span>'
    if r.get("file_match"):
        return '<span class="tag partial">FILE</span>'
    return '<span class="tag miss">MISS</span>'


def _result_row(r: dict[str, Any]) -> str:
    cves_extra = ", ".join(r.get("actual_cwes_found") or []) or "—"
    wall = r.get("wall_time_seconds", 0.0)
    return (
        f"<tr>"
        f"<td><code>{html.escape(r['slug'])}</code></td>"
        f"<td>{html.escape(r.get('cve_id', '—'))}</td>"
        f"<td>{_verdict_tag(r)}</td>"
        f"<td>{html.escape(r.get('expected_cwe', '—'))}</td>"
        f"<td>{html.escape(cves_extra)}</td>"
        f"<td class=num>{wall:.1f}s</td>"
        f"</tr>"
    )


def render_html(payload: dict[str, Any]) -> str:
    """Render the report payload as a self-contained HTML page."""
    report = payload["report"]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subtitle = (
        f"Generated {timestamp} · {report['total_tasks']} tasks · "
        f"{report['detected']} detected · subset {payload.get('subset', '?')}"
    )

    parts: list[str] = [_HTML_HEAD.format(title="Kryon CyberGym", subtitle=subtitle)]

    # KPI cards
    parts.append('<div class="kpi">')
    parts.append(
        f'<div><div class="label">Detection rate</div>'
        f'<div class="value">{report["detection_rate"] * 100:.1f}%</div></div>'
    )
    parts.append(
        f'<div><div class="label">Wilson 95% LB</div>'
        f'<div class="value">{report["wilson_lower_95"] * 100:.1f}%</div></div>'
    )
    parts.append(
        f'<div><div class="label">False positive rate</div>'
        f'<div class="value">{report["false_positive_rate"] * 100:.1f}%</div></div>'
    )
    parts.append(
        f'<div><div class="label">Tasks</div>'
        f'<div class="value">{report["total_tasks"]}</div></div>'
    )
    median = report.get("median_wall_seconds")
    median_str = f"{median:.1f}s" if median else "—"
    parts.append(
        f'<div><div class="label">Median wall</div>'
        f'<div class="value">{median_str}</div></div>'
    )
    parts.append("</div>")

    # Per-category breakdown
    by_category = report.get("by_category", {})
    if by_category:
        parts.append("<h2>By category</h2>")
        parts.append(
            "<table><thead><tr>"
            "<th>Category</th><th>Tasks</th><th>Detected</th>"
            "<th>Rate</th><th>Wilson 95% LB</th><th></th></tr></thead><tbody>"
        )
        for cat, m in sorted(by_category.items()):
            parts.append(
                f"<tr>"
                f"<td>{html.escape(cat)}</td>"
                f"<td class=num>{int(m['total'])}</td>"
                f"<td class=num>{int(m['detected'])}</td>"
                f"<td class=num>{m['detection_rate'] * 100:.1f}%</td>"
                f"<td class=num>{m['wilson_lower_95'] * 100:.1f}%</td>"
                f"<td>{_bar_html(m['detection_rate'])}</td>"
                f"</tr>"
            )
        parts.append("</tbody></table>")

    # Per-task table
    results = payload.get("results", [])
    if results:
        parts.append("<h2>Per-task results</h2>")
        parts.append(
            "<table><thead><tr>"
            "<th>Slug</th><th>CVE</th><th>Verdict</th>"
            "<th>Expected CWE</th><th>Agent CWEs</th><th>Wall</th>"
            "</tr></thead><tbody>"
        )
        for r in results:
            parts.append(_result_row(r))
        parts.append("</tbody></table>")

    parts.append(_HTML_FOOT)
    return "".join(parts)


def write_report(payload: dict[str, Any], out_path: Path) -> Path:
    """Render `payload` as HTML and write to `out_path`."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(payload), encoding="utf-8")
    return out_path
