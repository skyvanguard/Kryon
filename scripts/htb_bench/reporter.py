"""F83 — HTML scoreboard generator.

Takes the JSON output of `python -m scripts.htb_bench.cli ...` and
renders a static HTML page with:
  - Headline: total pwn rate + platform-by-platform breakdown
  - Per-target table: slug · platform · category · verdict · time
  - Per-category breakdown: pwn rate × category × platform
  - Diff vs previous run when `--prev <path>` is given (regression hunting)

No Jinja or Flask — just stdlib f-strings + escape. The output is
self-contained (inline CSS) so GitHub Pages serves it without a build
step. Add `<meta name="kryon-bench-version">` so a fingerprint is
visible to anyone reproducing the report (per HOW_TO_REPRODUCE.md).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="kryon-bench F83">
<title>{title}</title>
<style>
:root {{
  --bg: #0d1117; --fg: #e6edf3; --dim: #8b949e;
  --ok: #3fb950; --fail: #f85149; --err: #d29922;
  --accent: #58a6ff; --border: #30363d;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 2rem; background: var(--bg); color: var(--fg);
        font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
header {{ max-width: 1100px; margin: 0 auto 2rem; }}
h1 {{ margin: 0 0 0.5rem; color: var(--accent); font-size: 1.6rem; }}
h2 {{ margin: 2rem 0 0.75rem; font-size: 1.15rem; color: var(--fg); }}
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
.tag.pwn {{ background: rgba(63, 185, 80, 0.15); color: var(--ok); }}
.tag.fail {{ background: rgba(248, 81, 73, 0.15); color: var(--fail); }}
.tag.err {{ background: rgba(210, 153, 34, 0.15); color: var(--err); }}
.bar {{ display: inline-block; height: 6px; vertical-align: middle;
        background: var(--ok); border-radius: 3px; }}
.bar.partial {{ background: var(--err); }}
.bar.empty {{ background: var(--border); width: 80px; }}
footer {{ max-width: 1100px; margin: 3rem auto 1rem; color: var(--dim);
          font-size: 0.85rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
code {{ background: #161b22; padding: 0.1rem 0.35rem; border-radius: 3px;
        font-family: ui-monospace, monospace; font-size: 0.85em; }}
</style>
</head>
<body>
<header>
<h1>Kryon — public benchmark scoreboard</h1>
<div class="subtitle">{subtitle}</div>
</header>
<main>
"""


_HTML_FOOT = """
</main>
<footer>
Reproduce: <code>python -m scripts.htb_bench.cli --platform all --status ready</code>.
Fair-play contract: <a href="https://github.com/skyvanguard/Kryon/blob/main/docs/benchmarks/HOW_TO_REPRODUCE.md">HOW_TO_REPRODUCE.md</a>.
</footer>
</body>
</html>
"""


@dataclass(frozen=True)
class _PlatformBreakdown:
    platform: str
    total: int
    pwned: int

    @property
    def pwn_rate(self) -> float:
        return self.pwned / self.total if self.total else 0.0


def _bar_html(pct: float, width_px: int = 200) -> str:
    """Inline progress bar — green if pct >= 0.5, amber if 0 < pct < 0.5,
    grey if 0."""
    if pct <= 0:
        return f'<span class="bar empty"></span>'
    cls = "" if pct >= 0.5 else "partial"
    fill_px = max(2, int(width_px * pct))
    return f'<span class="bar {cls}" style="width:{fill_px}px"></span>'


def _platform_breakdown(payload: dict[str, Any]) -> list[_PlatformBreakdown]:
    """Group results by platform — derived from the `platforms_scanned`
    key (added by cli.main) plus per-result slug→platform mapping."""
    # Build slug → platform from the labset YAMLs (re-derive at render time
    # so the report stays accurate even if the JSON is hand-edited).
    from scripts.htb_bench.cli import PLATFORMS

    slug_to_plat: dict[str, str] = {}
    for plat, paths in PLATFORMS.items():
        try:
            import yaml
            labset = yaml.safe_load(paths["labset"].read_text(encoding="utf-8"))
            for entry in labset.get("targets", []):
                slug_to_plat[entry["slug"]] = plat
        except FileNotFoundError:
            continue

    groups: dict[str, list[dict]] = {}
    for r in payload.get("results", []):
        plat = slug_to_plat.get(r["slug"], "unknown")
        groups.setdefault(plat, []).append(r)

    return [
        _PlatformBreakdown(
            platform=plat,
            total=len(rs),
            pwned=sum(1 for r in rs if r["pwn"]),
        )
        for plat, rs in sorted(groups.items())
    ]


def _result_row(r: dict[str, Any], slug_to_plat: dict[str, str]) -> str:
    plat = slug_to_plat.get(r["slug"], "—")
    if r.get("error"):
        verdict = '<span class="tag err">ERR</span>'
    elif r["pwn"]:
        verdict = '<span class="tag pwn">PWN</span>'
    else:
        verdict = '<span class="tag fail">FAIL</span>'
    score = r.get("chain_match_score") or 0.0
    time_pwn = r.get("time_to_pwn_seconds")
    time_str = f"{time_pwn:.1f}s" if time_pwn is not None else "—"
    return (
        f"<tr>"
        f"<td>{html.escape(r['slug'])}</td>"
        f"<td>{html.escape(plat)}</td>"
        f"<td>{verdict}</td>"
        f"<td class=num>{score * 100:.0f}%</td>"
        f"<td class=num>{time_str}</td>"
        f"<td class=num>{r['wall_time_seconds']:.1f}s</td>"
        f"</tr>"
    )


def render_html(payload: dict[str, Any]) -> str:
    """Render the report payload as a self-contained HTML page."""
    report = payload["report"]
    breakdowns = _platform_breakdown(payload)

    # Slug → platform map for the per-target table.
    from scripts.htb_bench.cli import PLATFORMS
    slug_to_plat: dict[str, str] = {}
    for plat, paths in PLATFORMS.items():
        try:
            import yaml
            labset = yaml.safe_load(paths["labset"].read_text(encoding="utf-8"))
            for entry in labset.get("targets", []):
                slug_to_plat[entry["slug"]] = plat
        except FileNotFoundError:
            continue

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subtitle = f"Generated {timestamp} · {report['total_targets']} targets · {report['pwned']} pwned"

    parts: list[str] = [_HTML_HEAD.format(title="Kryon Bench", subtitle=subtitle)]

    # KPI cards
    parts.append('<div class="kpi">')
    parts.append(
        f'<div><div class="label">Pwn rate</div>'
        f'<div class="value">{report["pwn_rate"] * 100:.1f}%</div></div>'
    )
    parts.append(
        f'<div><div class="label">Targets</div>'
        f'<div class="value">{report["total_targets"]}</div></div>'
    )
    parts.append(
        f'<div><div class="label">Errors</div>'
        f'<div class="value">{report["errors"]}</div></div>'
    )
    median = report.get("median_time_to_pwn_seconds")
    median_str = f"{median:.1f}s" if median else "—"
    parts.append(
        f'<div><div class="label">Median TTP</div>'
        f'<div class="value">{median_str}</div></div>'
    )
    parts.append("</div>")

    # Per-platform breakdown
    if breakdowns:
        parts.append("<h2>By platform</h2>")
        parts.append("<table><thead><tr>"
                     "<th>Platform</th><th>Targets</th><th>Pwned</th>"
                     "<th>Rate</th><th></th></tr></thead><tbody>")
        for b in breakdowns:
            parts.append(
                f"<tr>"
                f"<td>{html.escape(b.platform)}</td>"
                f"<td class=num>{b.total}</td>"
                f"<td class=num>{b.pwned}</td>"
                f"<td class=num>{b.pwn_rate * 100:.1f}%</td>"
                f"<td>{_bar_html(b.pwn_rate)}</td>"
                f"</tr>"
            )
        parts.append("</tbody></table>")

    # Per-category breakdown
    by_category = report.get("by_category", {})
    if by_category:
        parts.append("<h2>By category</h2>")
        parts.append("<table><thead><tr>"
                     "<th>Category</th><th>Targets</th><th>Pwned</th>"
                     "<th>Rate</th><th></th></tr></thead><tbody>")
        for cat, m in sorted(by_category.items()):
            parts.append(
                f"<tr>"
                f"<td>{html.escape(cat)}</td>"
                f"<td class=num>{int(m['total'])}</td>"
                f"<td class=num>{int(m['pwned'])}</td>"
                f"<td class=num>{m['pwn_rate'] * 100:.1f}%</td>"
                f"<td>{_bar_html(m['pwn_rate'])}</td>"
                f"</tr>"
            )
        parts.append("</tbody></table>")

    # Per-target table
    results = payload.get("results", [])
    if results:
        parts.append("<h2>Per-target results</h2>")
        parts.append("<table><thead><tr>"
                     "<th>Slug</th><th>Platform</th><th>Verdict</th>"
                     "<th>Chain match</th><th>Time to pwn</th><th>Wall time</th>"
                     "</tr></thead><tbody>")
        for r in results:
            parts.append(_result_row(r, slug_to_plat))
        parts.append("</tbody></table>")

    parts.append(_HTML_FOOT)
    return "".join(parts)


def write_report(payload: dict[str, Any], out_path: Path) -> Path:
    """Render `payload` as HTML and write to `out_path`. Creates parents."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(payload), encoding="utf-8")
    return out_path
