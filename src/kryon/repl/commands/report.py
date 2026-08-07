"""/report — generate a PDF/HTML report from the session's persisted findings.

Closes the REPL → deliverable gap: after `analizá X`, the engine findings are
persisted (findings_bridge, Workstream A); this command turns them into a
client report in one step instead of `/findings export` + `kryon report`.

Usage:
  /report                                   → technical PDF, all findings
  /report --type executive --format pdf
  /report --client "Example Corp" --scope "www.example.com"
"""

from __future__ import annotations

import asyncio
import json

from rich.console import Console

from kryon.repl.commands.base import Command, register_command

console = Console()


def _get_store():
    from kryon.memory.store import MemoryStore

    return MemoryStore()


def _parse_flags(args: list[str] | None) -> dict[str, str]:
    opts = {"type": "technical", "format": "pdf", "client": "", "scope": ""}
    if not args:
        return opts
    i = 0
    while i < len(args):
        key = args[i].lstrip("-")
        if key in opts and i + 1 < len(args):
            opts[key] = args[i + 1]
            i += 2
        else:
            i += 1
    return opts


def _load_findings() -> list:
    from kryon.cli.findings_collector import CLIFindingsCollector
    from kryon.intelligence.models import Finding

    store = _get_store()
    findings: list = []
    seen: set[str] = set()
    for rec in store.list_all_findings(limit=1000):
        try:
            f = Finding.model_validate(json.loads(rec.finding_json))
        except Exception:  # noqa: BLE001 — skip unparseable records
            continue
        # Dedup by content signature so a re-run / cross-session accumulation
        # doesn't ship duplicate findings in the deliverable.
        sig = CLIFindingsCollector.finding_signature(f)
        if sig in seen:
            continue
        seen.add(sig)
        findings.append(f)
    return findings


def handle_report(args: list[str] | None = None) -> bool:
    opts = _parse_flags(args)
    findings = _load_findings()
    if not findings:
        console.print("[yellow]No hay hallazgos persistidos para reportar.[/yellow]")
        console.print("[dim]Corré un análisis primero (ej. 'analizá https://target').[/dim]")
        return True

    try:
        from kryon.reporting.export import save_pdf, save_report
        from kryon.reporting.generator import ReportGenerator
        from kryon.reporting.models import ReportConfig, ReportType
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]reporting no disponible ({exc}). Instalá el extra: pip install kryon[reporting][/red]")
        return False

    try:
        rtype = ReportType(opts["type"])
    except ValueError:
        rtype = ReportType.TECHNICAL

    config = ReportConfig(
        report_type=rtype,
        client_name=opts["client"],
        target_scope=opts["scope"],
        format=opts["format"],
    )
    console.print(f"[dim]Generando informe {rtype.value} con {len(findings)} hallazgo(s)…[/dim]")

    try:
        gen = ReportGenerator()
        html = asyncio.run(gen.generate(findings, config))
        if opts["format"].lower() == "pdf":
            pdf_bytes = asyncio.run(gen.to_pdf(html))
            path = save_pdf(pdf_bytes, opts["client"], rtype.value)
        else:
            path = save_report(html, opts["client"], rtype.value)
        console.print(f"[green]✔ Informe guardado:[/green] {path}")
    except ImportError:
        console.print("[red]Falta weasyprint para PDF. Usá --format html o instalá kryon[reporting].[/red]")
        return False
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Falló la generación del informe: {exc}[/red]")
        return False
    return True


class ReportCommand(Command):
    """Single-shot command — all args are flags, no subcommands."""

    def handle(self, args: list[str] | None = None) -> bool:
        return handle_report(args)


report_cmd = ReportCommand(
    "report",
    "Genera un informe (PDF/HTML) de los hallazgos de la sesión",
    aliases=["reporte"],
)
register_command(report_cmd)
