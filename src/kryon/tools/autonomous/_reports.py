"""Autonomous/pentest markdown report generators.

Extraído de ``orchestrator.py`` (era 1612 líneas → split en módulos).
"""

from __future__ import annotations

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _generate_autonomous_report(results: dict, output_path: str):
    """Generate autonomous operation report."""
    with open(output_path, "w") as f:
        f.write("# KRYON Autonomous CTF Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        f.write("## Results\n\n")
        f.write(f"- Flags Found: {len(results['flags_found'])}\n")
        f.write(f"- Time Elapsed: {results['time_elapsed']:.2f} seconds\n")
        f.write(f"- Privilege Level: {results['privilege_level']}\n\n")
        f.write("## Exploitation Path\n\n")
        for step in results["exploitation_path"]:
            f.write(f"- {step}\n")


def _generate_pentest_report(results: dict, output_path: str) -> None:
    """Write the autonomous_pentest markdown report.

    Was a ``pass`` stub — so ``results['report_path']`` pointed at a file that
    never existed. Renders the aggregate: scope summary, compromised hosts,
    confirmed vulnerabilities, loot, and lateral-movement paths. Defensive with
    ``.get()`` so a partial/aborted result still produces a report."""
    discovered = results.get("hosts_discovered", []) or []
    out_of_scope = results.get("hosts_out_of_scope", []) or []
    compromised = results.get("compromised_hosts", []) or []
    vulns = results.get("vulnerabilities", []) or []
    loot = results.get("data_found", []) or []
    lateral = results.get("lateral_movement_paths", []) or []

    lines: list[str] = [
        "# KRYON Autonomous Pentest Report",
        "",
        f"**Generated:** {datetime.now().isoformat()}",
        f"**Status:** {'SUCCESS' if results.get('success') else 'no compromise'}",
    ]
    if results.get("error"):
        lines.append(f"**Error:** {results['error']}")

    lines += [
        "",
        "## Summary",
        "",
        f"- In-scope hosts assessed: {len(discovered)}",
        f"- Out-of-scope hosts skipped: {len(out_of_scope)}",
        f"- Hosts compromised: {len(compromised)}",
        f"- Vulnerabilities confirmed: {len(vulns)}",
        f"- Data/loot recovered: {len(loot)}",
        f"- Lateral-movement paths: {len(lateral)}",
    ]

    if out_of_scope:
        lines += ["", "## Out-of-scope (skipped)", ""]
        lines += [f"- `{ip}`" for ip in out_of_scope]

    if compromised:
        lines += ["", "## Compromised hosts", ""]
        for host in compromised:
            flags = host.get("flags_found", []) or []
            lines.append(
                f"- `{host.get('ip', '?')}` — privilege: **{host.get('privilege_level', 'none')}**"
                f" · flags: {len(flags)}"
            )

    if vulns:
        lines += ["", "## Vulnerabilities", ""]
        for v in vulns:
            lines.append(
                f"- `{v.get('host', '?')}` · {v.get('service', v.get('type', '?'))} — {v.get('type', 'finding')}"
            )

    if loot:
        lines += ["", "## Data recovered", ""]
        for d in loot:
            lines.append(f"- `{d.get('host', '?')}` — {d.get('flag', d)}")

    if lateral:
        lines += ["", "## Lateral movement", ""]
        for path in lateral:
            lines.append(f"- {path}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
