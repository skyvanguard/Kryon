"""Findings command for KRYON REPL — view and manage persisted findings."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from kryon.repl.commands.base import Command, register_command

console = Console()


def _get_store():
    from kryon.memory.store import MemoryStore

    return MemoryStore()


def _severity_color(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim white",
    }.get(severity, "white")


def handle_list(args: list[str] | None = None) -> bool:
    """List recent findings."""
    store = _get_store()
    limit = 20
    severity = None

    if args:
        for arg in args:
            if arg.isdigit():
                limit = int(arg)
            elif arg.lower() in ("critical", "high", "medium", "low", "info"):
                severity = arg.lower()

    findings = store.list_all_findings(severity=severity, limit=limit)

    if not findings:
        console.print("[dim]No findings found.[/dim]")
        return True

    table = Table(title=f"Findings ({len(findings)})", show_header=True, header_style="bold white")
    table.add_column("ID", style="dim", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=40)
    table.add_column("Asset", width=20)
    table.add_column("Status", width=12)

    for record in findings:
        try:
            data = json.loads(record.finding_json)
            sev = data.get("severity", "info")
            table.add_row(
                record.id,
                f"[{_severity_color(sev)}]{sev.upper()}[/{_severity_color(sev)}]",
                data.get("title", "N/A")[:40],
                data.get("affected_asset", "N/A")[:20],
                record.status,
            )
        except Exception:
            table.add_row(record.id, "?", "Parse error", "", record.status)

    console.print(table)
    return True


def handle_show(args: list[str] | None = None) -> bool:
    """Show full details for a finding by ID."""
    if not args:
        console.print("[yellow]Usage: /findings show <id>[/yellow]")
        return False

    store = _get_store()
    record = store.get_finding_by_id(args[0])
    if not record:
        console.print(f"[red]Finding '{args[0]}' not found.[/red]")
        return False

    try:
        data = json.loads(record.finding_json)
        sev = data.get("severity", "info")
        console.print(f"\n[bold]Finding: {record.id}[/bold]")
        console.print(f"  Title:    {data.get('title', 'N/A')}")
        console.print(f"  Severity: [{_severity_color(sev)}]{sev.upper()}[/{_severity_color(sev)}]")
        console.print(f"  Asset:    {data.get('affected_asset', 'N/A')}")
        console.print(f"  CVSS:     {data.get('cvss_score', 'N/A')}")
        console.print(f"  Source:   {data.get('tool_source', 'N/A')}")
        console.print(f"  Status:   {record.status}")
        console.print(f"  Scan ID:  {record.scan_id}")
        desc = data.get("description", "")
        if desc:
            console.print(f"\n  [dim]Description:[/dim]\n  {desc[:500]}")
        evidence = data.get("evidence", "")
        if evidence:
            console.print(f"\n  [dim]Evidence:[/dim]\n  {evidence[:300]}")
        console.print()
    except Exception as exc:
        console.print(f"[red]Error parsing finding: {exc}[/red]")

    return True


def handle_export(args: list[str] | None = None) -> bool:
    """Export findings to a JSON file."""
    store = _get_store()
    findings = store.list_all_findings(limit=1000)

    if not findings:
        console.print("[dim]No findings to export.[/dim]")
        return True

    output_path = args[0] if args else "kryon_findings.json"
    export_data = []
    for record in findings:
        try:
            data = json.loads(record.finding_json)
            data["_record_id"] = record.id
            data["_scan_id"] = record.scan_id
            data["_status"] = record.status
            export_data.append(data)
        except Exception:
            continue

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Exported {len(export_data)} findings to {output_path}[/green]")
    except OSError as exc:
        console.print(f"[red]Failed to write {output_path}: {exc}[/red]")
    return True


# Register command
findings_cmd = Command("findings", "View and manage persisted findings", aliases=["f"])
findings_cmd.add_subcommand("list", "List recent findings (optionally filter by severity)", handle_list)
findings_cmd.add_subcommand("show", "Show full details for a finding", handle_show)
findings_cmd.add_subcommand("export", "Export findings to JSON file", handle_export)
register_command(findings_cmd)
