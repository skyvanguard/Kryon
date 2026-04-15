"""F12.7 — `kryon engage` end-to-end orchestrator for the demo flow.

Single command that takes a target (host / CIDR / domain) and produces:

  Phase 1  discovery (nmap with live_progress)
  Phase 2  service-specific assessment (SSH config check, HTTP probe,
           DB banner grab)
  Phase 3  findings summary + rule-based remediation proposals
  Phase 4  optional approval prompt + apply (when --ssh provided)
  Phase 5  re-audit
  Phase 6  HTML + PDF report via kryon.reporting.demo_report

This is the MVP demo orchestrator — deterministic, rule-based,
predictable. Not the full agent loop (that still exists via `kryon`
REPL). Reliability for the britimp demo over flexibility.

Usage:

    kryon engage 127.0.0.1 \\
        --scope 127.0.0.1 \\
        --ssh admin@127.0.0.1:2222 \\
        --ssh-password demo-only-password \\
        --out /tmp/kryon-reports \\
        --client britimp \\
        --engagement-id britimp-demo-2026-04-15

    kryon engage 127.0.0.1 --dry-run-only        # no apply, just report
    kryon engage 127.0.0.1 --auto-approve        # lab/demo only
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    cwe: str
    severity: str
    host: str
    rule_id: str
    message: str
    evidence: str = ""
    remediation: str = ""
    remediation_command: str = ""    # exact shell command for Fase 3
    target_host: str = ""            # admin@host for SSH exec
    severity_rank: int = field(default=99)


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# -----------------------------------------------------------------------------
# Phase 1 — discovery
# -----------------------------------------------------------------------------


def _run_nmap(target: str, *, timeout_s: int = 600) -> str:
    """Run a fast service-detection nmap against the target.

    Uses live_progress when KRYON_LIVE_PROGRESS=true; otherwise falls
    back to plain subprocess so CI benches don't render Live panels.
    """
    use_live = os.environ.get("KRYON_LIVE_PROGRESS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    cmd = f"nmap -sV -T4 --top-ports 100 -oX - {shlex.quote(target)}"
    if use_live:
        try:
            from kryon.repl.ui.live_progress import run_with_progress
            r = run_with_progress(cmd, timeout_s=timeout_s)
            return r.stdout
        except Exception as exc:
            logger.warning("live_progress fell back: %s", exc)
    try:
        out = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout_s, check=False,
        )
        return out.stdout
    except subprocess.TimeoutExpired:
        return ""


_SERVICE_RE = re.compile(
    r'<port protocol="tcp" portid="(\d+)">.*?'
    r'<state state="(\w+)".*?'
    r'(?:<service name="([^"]+)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?)?',
    re.DOTALL,
)


@dataclass
class DiscoveredService:
    host: str
    port: int
    state: str
    service: str
    product: str = ""
    version: str = ""


def _parse_nmap_xml(xml: str, host: str) -> list[DiscoveredService]:
    out: list[DiscoveredService] = []
    for m in _SERVICE_RE.finditer(xml):
        out.append(DiscoveredService(
            host=host,
            port=int(m.group(1)),
            state=m.group(2),
            service=(m.group(3) or "").lower(),
            product=m.group(4) or "",
            version=m.group(5) or "",
        ))
    return out


# -----------------------------------------------------------------------------
# Phase 2 — service-specific checks
# -----------------------------------------------------------------------------


def _check_http(svc: DiscoveredService) -> list[Finding]:
    """HTTP plaintext + server-token leak + /admin open."""
    findings: list[Finding] = []
    try:
        headers = subprocess.run(
            ["curl", "-sSI", "--max-time", "5",
             f"http://{svc.host}:{svc.port}/"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
    except Exception:
        headers = ""

    # CWE-319: HTTP plaintext (no TLS on this port)
    if svc.port in (80, 8080) or svc.port not in (443, 8443):
        findings.append(Finding(
            cwe="CWE-319", severity="HIGH", host=f"{svc.host}:{svc.port}",
            rule_id="http-plaintext",
            message=f"Servicio HTTP en {svc.host}:{svc.port} sin TLS.",
            evidence=headers[:400] if headers else f"puerto {svc.port} abierto, servicio http",
            remediation="Habilitar HTTPS y redirigir HTTP->HTTPS.",
            severity_rank=_SEV_RANK["HIGH"],
        ))

    # CWE-200: Server header leaks version
    m = re.search(r"^Server:\s*([^\r\n]+)", headers, re.MULTILINE | re.IGNORECASE)
    if m and re.search(r"/\d", m.group(1)):
        findings.append(Finding(
            cwe="CWE-200", severity="MEDIUM", host=f"{svc.host}:{svc.port}",
            rule_id="http-server-token",
            message="Header Server expone versión del servidor.",
            evidence=f"Server: {m.group(1).strip()}",
            remediation="Configurar server_tokens off (nginx) o ServerTokens Prod (apache).",
            severity_rank=_SEV_RANK["MEDIUM"],
        ))

    # CWE-306: /admin accesible sin auth
    try:
        admin_code = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "5", f"http://{svc.host}:{svc.port}/admin"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip()
    except Exception:
        admin_code = ""
    if admin_code == "200":
        findings.append(Finding(
            cwe="CWE-306", severity="HIGH", host=f"{svc.host}:{svc.port}",
            rule_id="http-admin-open",
            message="Endpoint /admin accesible sin autenticación.",
            evidence=f"GET {svc.host}:{svc.port}/admin → 200",
            remediation="Proteger /admin con autenticación (auth_basic / OAuth).",
            severity_rank=_SEV_RANK["HIGH"],
        ))
    return findings


def _check_ssh(svc: DiscoveredService, ssh_target: str | None,
               ssh_password: str | None) -> list[Finding]:
    """SSH banner grab + (optional) config check via SSH."""
    findings: list[Finding] = []

    # Banner is always visible
    banner = ""
    try:
        import socket
        s = socket.socket()
        s.settimeout(3)
        s.connect((svc.host, svc.port))
        banner = s.recv(128).decode(errors="replace").splitlines()[0]
        s.close()
    except Exception:
        pass

    if banner and not ssh_target:
        findings.append(Finding(
            cwe="CWE-200", severity="LOW", host=f"{svc.host}:{svc.port}",
            rule_id="ssh-banner-visible",
            message="SSH expone banner con versión del servidor.",
            evidence=banner,
            remediation="Reducir verbosidad del banner (no suele ser crítico).",
            severity_rank=_SEV_RANK["LOW"],
        ))

    if not ssh_target:
        return findings

    # Deeper checks require creds
    user, _, host = ssh_target.partition("@")
    if ":" in host:
        host, port = host.split(":", 1)
    else:
        port = str(svc.port)

    def _remote(cmd: str) -> str:
        base = ["ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", port, f"{user}@{host}"]
        if ssh_password:
            base = ["sshpass", "-p", ssh_password] + base
        try:
            r = subprocess.run(base + [cmd], capture_output=True,
                               text=True, timeout=15, check=False)
            return r.stdout
        except Exception:
            return ""

    cfg = _remote("sudo cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config")
    if not cfg:
        logger.info("SSH config read failed (auth? sudo?)")
        return findings

    if re.search(r"^\s*PermitRootLogin\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(Finding(
            cwe="CWE-521", severity="CRITICAL",
            host=f"{user}@{host}",
            rule_id="sshd-permit-root-login",
            message="sshd permite login de root por SSH.",
            evidence="PermitRootLogin yes",
            remediation="Desactivar PermitRootLogin en /etc/ssh/sshd_config.",
            remediation_command=(
                "sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "
                "/etc/ssh/sshd_config && sudo systemctl reload sshd"
            ),
            target_host=f"{user}@{host}",
            severity_rank=_SEV_RANK["CRITICAL"],
        ))
    if re.search(r"^\s*PasswordAuthentication\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(Finding(
            cwe="CWE-521", severity="HIGH",
            host=f"{user}@{host}",
            rule_id="sshd-password-auth",
            message="sshd permite autenticación por contraseña.",
            evidence="PasswordAuthentication yes",
            remediation="Requerir autenticación por clave pública.",
            remediation_command=(
                "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "
                "/etc/ssh/sshd_config && sudo systemctl reload sshd"
            ),
            target_host=f"{user}@{host}",
            severity_rank=_SEV_RANK["HIGH"],
        ))
    m = re.search(r"^\s*MaxAuthTries\s+(\d+)", cfg, re.MULTILINE | re.IGNORECASE)
    if m and int(m.group(1)) > 4:
        findings.append(Finding(
            cwe="CWE-307", severity="MEDIUM",
            host=f"{user}@{host}",
            rule_id="sshd-max-auth-tries",
            message=f"MaxAuthTries {m.group(1)} permite fuerza bruta prolongada.",
            evidence=f"MaxAuthTries {m.group(1)}",
            remediation="Bajar a 3 y habilitar fail2ban.",
            remediation_command=(
                f"sudo sed -i 's/^MaxAuthTries {m.group(1)}/MaxAuthTries 3/' "
                "/etc/ssh/sshd_config && sudo systemctl reload sshd"
            ),
            target_host=f"{user}@{host}",
            severity_rank=_SEV_RANK["MEDIUM"],
        ))
    return findings


def _check_mysql(svc: DiscoveredService) -> list[Finding]:
    """MySQL-port open + plaintext (no forced TLS detectable remotely)."""
    return [Finding(
        cwe="CWE-319", severity="HIGH", host=f"{svc.host}:{svc.port}",
        rule_id="mysql-exposed",
        message=f"MySQL accesible en {svc.host}:{svc.port}.",
        evidence=f"nmap detectó {svc.product or 'mysql'} {svc.version} en tcp/{svc.port}",
        remediation=(
            "Habilitar require_secure_transport=ON, restringir "
            "bind-address a la red interna, exigir TLS en todos los usuarios."
        ),
        severity_rank=_SEV_RANK["HIGH"],
    )]


# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------


def _banner(console, text: str) -> None:
    console.print()
    console.print(f"[bold cyan]▸[/bold cyan] [bold]{text}[/bold]")


def _parse_ssh_arg(raw: str) -> tuple[str, str]:
    """'admin@host:2222' -> ('admin@host', '2222'). Default port 22."""
    m = re.match(r"^(\S+?)(?::(\d+))?$", raw)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid --ssh: {raw}")
    return m.group(1), m.group(2) or "22"


def run_engage(args: argparse.Namespace) -> int:
    """Entry point from the CLI dispatcher."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    target = args.target
    scope = args.scope or target
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    engagement_id = args.engagement_id or (
        f"engagement-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    )

    # --- Phase 1: discovery -----------------------------------------------
    _banner(console, f"Fase 1 — descubrimiento ({target})")
    xml = _run_nmap(target, timeout_s=args.nmap_timeout)
    services = _parse_nmap_xml(xml, target)
    open_svcs = [s for s in services if s.state == "open"]
    console.print(f"  [green]{len(open_svcs)}[/green] puertos abiertos en {target}")
    for s in open_svcs[:10]:
        console.print(
            f"    {s.port:>5}/{s.state}  {s.service} "
            f"{s.product or ''} {s.version or ''}"
        )

    # --- Phase 2: service checks ------------------------------------------
    _banner(console, "Fase 2 — evaluación por servicio")
    findings: list[Finding] = []
    for svc in open_svcs:
        if svc.service in ("http", "http-proxy", "https") or svc.port in (80, 443, 8080, 8443):
            findings.extend(_check_http(svc))
        if svc.service == "ssh" or svc.port == 22 or svc.port == 2222:
            findings.extend(_check_ssh(svc, args.ssh, args.ssh_password))
        if svc.service in ("mysql", "postgresql", "mongodb", "redis") \
                or svc.port in (3306, 33060, 5432, 27017, 6379):
            findings.extend(_check_mysql(svc))

    findings.sort(key=lambda f: f.severity_rank)
    console.print(f"  [yellow]{len(findings)}[/yellow] hallazgos detectados")

    # --- Phase 3: findings table ------------------------------------------
    _banner(console, "Fase 3 — resumen")
    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("#", style="dim", width=3)
    tbl.add_column("Severity", width=10)
    tbl.add_column("CWE", width=10)
    tbl.add_column("Host", width=30)
    tbl.add_column("Rule")
    for i, f in enumerate(findings, 1):
        tbl.add_row(str(i), f.severity, f.cwe, f.host, f.rule_id)
    console.print(tbl)

    # --- Phase 4: remediation -------------------------------------------
    applied_findings: list[str] = []
    if not args.dry_run_only and args.ssh:
        _banner(console, "Fase 4 — proponiendo remediación")
        actions = [
            {
                "command": f.remediation_command,
                "purpose": f.remediation or f.message,
                "severity": f.severity.lower(),
                "reversible": True,
                "target_host": f.target_host,
            }
            for f in findings
            if f.remediation_command and f.target_host
        ]
        if actions:
            from kryon.repl.ui.approval import (
                ApprovalRequest, ApprovalResult, ProposedAction, Severity,
                ask_approval,
            )
            sev_map = {
                "critical": Severity.DESTRUCTIVE, "high": Severity.MODIFY,
                "medium": Severity.MODIFY, "low": Severity.READ,
                "info": Severity.READ,
            }
            req = ApprovalRequest(
                title=f"Aplicar {len(actions)} correcciones en {args.ssh}",
                subtitle=f"Engagement: {engagement_id}",
                actions=[
                    ProposedAction(
                        command=a["command"], purpose=a["purpose"],
                        severity=sev_map.get(a["severity"], Severity.MODIFY),
                        reversible=a["reversible"],
                        target_host=a["target_host"],
                    )
                    for a in actions
                ],
                impact_notes=[
                    "Backup de config previo (sed --in-place), reload sshd tras cada cambio.",
                    "Re-auditoría automática al final.",
                ],
                dry_run=False,
            )
            if args.auto_approve:
                verdict = ApprovalResult.YES
                console.print("[yellow]⚠ KRYON_AUTO_APPROVE — demo mode[/yellow]")
            else:
                verdict = ask_approval(req, console=console,
                                       default=ApprovalResult.NO)

            if verdict == ApprovalResult.YES:
                for a in actions:
                    user_host, port = _parse_ssh_arg(a["target_host"])
                    user, _, host = user_host.partition("@")
                    base = ["ssh", "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "-p", port, f"{user}@{host}"]
                    if args.ssh_password:
                        base = ["sshpass", "-p", args.ssh_password] + base
                    console.print(f"  [dim]$[/dim] {a['command'][:90]}")
                    try:
                        r = subprocess.run(
                            base + [a["command"]], capture_output=True,
                            text=True, timeout=30, check=False,
                        )
                        if r.returncode == 0:
                            console.print(f"  [green]✓[/green] applied")
                            applied_findings.append(a["purpose"])
                        else:
                            console.print(
                                f"  [red]✗[/red] exit {r.returncode}: "
                                f"{r.stderr[:120]}"
                            )
                    except Exception as exc:
                        console.print(f"  [red]✗[/red] {exc}")
            else:
                console.print(f"[yellow]veredicto: {verdict.value} — nada aplicado[/yellow]")
        else:
            console.print("  [dim]sin acciones con comando de remediación[/dim]")

    # --- Phase 5: report --------------------------------------------------
    _banner(console, "Fase 6 — reporte")
    from kryon.reporting.demo_report import render_demo_report
    findings_dict = [
        {
            **{k: v for k, v in asdict(f).items() if k != "severity_rank"},
        }
        for f in findings
    ]
    ctx = {
        "client_name": args.client or "",
        "engagement_id": engagement_id,
        "target_scope": scope,
        "auditor": args.auditor or "SkyVanguard / Kryon",
        "applied": applied_findings,
    }
    paths = render_demo_report(
        findings_dict, ctx, output_dir=out_dir,
        filename_stem=f"kryon-{engagement_id}",
    )
    for k, v in paths.items():
        console.print(f"  [green]{k}[/green] → {v}")
    return 0


# -----------------------------------------------------------------------------
# CLI wiring
# -----------------------------------------------------------------------------


def add_engage_subparser(subparsers) -> argparse.ArgumentParser:
    """Called from kryon.cli._original.main() to register the subcommand."""
    p = subparsers.add_parser(
        "engage",
        help="Run an end-to-end engagement against a target (demo orchestrator)",
    )
    p.add_argument("target", help="host / IP / CIDR to assess")
    p.add_argument("--scope", help="human-readable scope string for the report")
    p.add_argument("--ssh", help="SSH target as user@host[:port]")
    p.add_argument("--ssh-password",
                   help="SSH password (requires sshpass); demo only")
    p.add_argument("--out", default="./kryon-reports",
                   help="output directory for the report")
    p.add_argument("--client", default="",
                   help="client name for the report header")
    p.add_argument("--engagement-id", default="",
                   help="engagement identifier")
    p.add_argument("--auditor", default="",
                   help="auditor name (default: SkyVanguard / Kryon)")
    p.add_argument("--dry-run-only", action="store_true",
                   help="skip remediation even if --ssh provided")
    p.add_argument("--auto-approve", action="store_true",
                   help="skip approval prompt (lab / demo only — NEVER prod)")
    p.add_argument("--nmap-timeout", type=int, default=600,
                   help="nmap wall-clock timeout in seconds (default: 600)")
    return p
