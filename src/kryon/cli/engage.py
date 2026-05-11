"""F12.7 / F77.A — `kryon engage` end-to-end orchestrator.

Single command that takes a target (host / CIDR / domain) and produces:

  Phase 1  discovery (nmap with live_progress)
  Phase 2  service-specific assessment (SSH config check, HTTP probe,
           DB banner grab)
  Phase 2b optional compliance audit (F77.A — when --framework given)
  Phase 3  findings summary + rule-based remediation proposals
  Phase 4  optional approval prompt + apply (when --ssh provided)
  Phase 5  re-audit
  Phase 6  HTML + PDF report. When --framework is used the consolidated
           multi-framework PDF is produced; otherwise the demo_report.

F77.A wires engage into the rest of the stack:
- `--framework FW[,FW2,...]` runs the compliance runner and consolidates
  findings into the multi-framework PDF (F44).
- `--use-agent` / KRYON_ENGAGE_AGENT=true bolts the unified Kryon agent
  onto the tail of Phase 2 for LLM-driven deepening of the findings
  surface. Off by default to preserve demo determinism.

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
    kryon engage 127.0.0.1 --framework pci_dss,bcp_py  # compliance sweep
    kryon engage 127.0.0.1 --use-agent           # agent-driven deepening
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
    remediation_command: str = ""  # exact shell command for Fase 3
    target_host: str = ""  # admin@host for SSH exec
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
        "1",
        "true",
        "yes",
        "on",
    }
    # -Pn: skip host discovery. Required when the target firewall
    # filters ICMP (typical for hardened hosts and PVE behind FortiGate).
    # Without -Pn, nmap concludes "host is down" and emits no ports even
    # though TCP services are reachable.
    # -sT: TCP connect scan. Default -sV picks -sS (raw SYN) which needs
    # Npcap/raw sockets — unavailable on Windows hosts without admin
    # install. -sT works as a non-privileged user on every platform.
    cmd = f"nmap -Pn -sT -sV -T4 --top-ports 100 -oX - {shlex.quote(target)}"
    if use_live:
        try:
            from kryon.repl.ui.live_progress import run_with_progress

            r = run_with_progress(cmd, timeout_s=timeout_s)
            return r.stdout
        except Exception as exc:
            logger.warning("live_progress fell back: %s", exc)
    try:
        out = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
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
        out.append(
            DiscoveredService(
                host=host,
                port=int(m.group(1)),
                state=m.group(2),
                service=(m.group(3) or "").lower(),
                product=m.group(4) or "",
                version=m.group(5) or "",
            )
        )
    return out


# -----------------------------------------------------------------------------
# Phase 2 — service-specific checks
# -----------------------------------------------------------------------------


def _check_http(svc: DiscoveredService) -> list[Finding]:
    """HTTP plaintext + server-token leak + /admin open."""
    findings: list[Finding] = []
    try:
        headers = subprocess.run(
            ["curl", "-sSI", "--max-time", "5", f"http://{svc.host}:{svc.port}/"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout
    except Exception:
        headers = ""

    # CWE-319: HTTP plaintext (no TLS on this port)
    if svc.port in (80, 8080) or svc.port not in (443, 8443):
        findings.append(
            Finding(
                cwe="CWE-319",
                severity="HIGH",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-plaintext",
                message=f"Servicio HTTP en {svc.host}:{svc.port} sin TLS.",
                evidence=headers[:400] if headers else f"puerto {svc.port} abierto, servicio http",
                remediation="Habilitar HTTPS y redirigir HTTP->HTTPS.",
                severity_rank=_SEV_RANK["HIGH"],
            )
        )

    # CWE-200: Server header leaks version
    m = re.search(r"^Server:\s*([^\r\n]+)", headers, re.MULTILINE | re.IGNORECASE)
    if m and re.search(r"/\d", m.group(1)):
        findings.append(
            Finding(
                cwe="CWE-200",
                severity="MEDIUM",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-server-token",
                message="Header Server expone versión del servidor.",
                evidence=f"Server: {m.group(1).strip()}",
                remediation="Configurar server_tokens off (nginx) o ServerTokens Prod (apache).",
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )

    # CWE-306: /admin accesible sin auth
    try:
        admin_code = subprocess.run(
            [
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                f"http://{svc.host}:{svc.port}/admin",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except Exception:
        admin_code = ""
    if admin_code == "200":
        findings.append(
            Finding(
                cwe="CWE-306",
                severity="HIGH",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-admin-open",
                message="Endpoint /admin accesible sin autenticación.",
                evidence=f"GET {svc.host}:{svc.port}/admin → 200",
                remediation="Proteger /admin con autenticación (auth_basic / OAuth).",
                severity_rank=_SEV_RANK["HIGH"],
            )
        )
    return findings


def _check_ssh(svc: DiscoveredService, ssh_target: str | None, ssh_password: str | None) -> list[Finding]:
    """SSH banner grab + (optional) config check via SSH."""
    findings: list[Finding] = []

    # Banner is always visible. Use a context manager so the socket closes
    # even when recv times out or the peer resets — leaked FDs were real
    # across long engagements.
    import socket

    banner = ""
    try:
        with socket.create_connection((svc.host, svc.port), timeout=3) as s:
            raw = s.recv(128).decode(errors="replace").splitlines()
            banner = raw[0] if raw else ""
    except (TimeoutError, OSError) as exc:
        logger.debug("ssh banner grab failed on %s:%s: %s", svc.host, svc.port, exc)

    if banner and not ssh_target:
        findings.append(
            Finding(
                cwe="CWE-200",
                severity="LOW",
                host=f"{svc.host}:{svc.port}",
                rule_id="ssh-banner-visible",
                message="SSH expone banner con versión del servidor.",
                evidence=banner,
                remediation="Reducir verbosidad del banner (no suele ser crítico).",
                severity_rank=_SEV_RANK["LOW"],
            )
        )

    if not ssh_target:
        return findings

    # Deeper checks require creds
    user, _, host = ssh_target.partition("@")
    if ":" in host:
        host, port = host.split(":", 1)
    else:
        port = str(svc.port)

    def _remote(cmd: str) -> str:
        base = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            port,
            f"{user}@{host}",
        ]
        # Pass password via env (`sshpass -e`) so it never appears in argv
        # / /proc/<pid>/cmdline. Banks regularly audit running processes;
        # `sshpass -p <password>` is a reliable demo killer.
        env = None
        if ssh_password:
            env = {**os.environ, "SSHPASS": ssh_password}
            base = ["sshpass", "-e"] + base
        try:
            r = subprocess.run(base + [cmd], capture_output=True, text=True, timeout=15, check=False, env=env)
            return r.stdout
        except Exception:
            return ""

    cfg = _remote("sudo cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config")
    if not cfg:
        logger.info("SSH config read failed (auth? sudo?)")
        return findings

    if re.search(r"^\s*PermitRootLogin\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                cwe="CWE-521",
                severity="CRITICAL",
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
            )
        )
    if re.search(r"^\s*PasswordAuthentication\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                cwe="CWE-521",
                severity="HIGH",
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
            )
        )
    m = re.search(r"^\s*MaxAuthTries\s+(\d+)", cfg, re.MULTILINE | re.IGNORECASE)
    if m and int(m.group(1)) > 4:
        findings.append(
            Finding(
                cwe="CWE-307",
                severity="MEDIUM",
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
            )
        )
    return findings


def _check_mysql(svc: DiscoveredService) -> list[Finding]:
    """MySQL-port open + plaintext (no forced TLS detectable remotely)."""
    return [
        Finding(
            cwe="CWE-319",
            severity="HIGH",
            host=f"{svc.host}:{svc.port}",
            rule_id="mysql-exposed",
            message=f"MySQL accesible en {svc.host}:{svc.port}.",
            evidence=f"nmap detectó {svc.product or 'mysql'} {svc.version} en tcp/{svc.port}",
            remediation=(
                "Habilitar require_secure_transport=ON, restringir "
                "bind-address a la red interna, exigir TLS en todos los usuarios."
            ),
            severity_rank=_SEV_RANK["HIGH"],
        )
    ]


# -----------------------------------------------------------------------------
# F77.A — compliance + agent integration
# -----------------------------------------------------------------------------


def _run_compliance(
    frameworks: list[str],
    *,
    host: str,
    ssh_target: str | None,
    ssh_password: str | None,
    ssh_key: str | None,
) -> dict[str, list[dict]]:
    """Run the compliance runner per framework.

    Returns a dict keyed by framework id with CheckResult-dict lists
    ready to feed ``multi_framework_pdf.render_multi_framework_pdf``.
    """
    from kryon.compliance.checks.base import CheckContext
    from kryon.compliance.runner import (
        _import_all_checks,
        registered_checks,
        run_all,
    )

    # Side-effect import populates _REGISTERED_CHECKS.
    _import_all_checks()

    ssh_user = ""
    ssh_port = 22
    if ssh_target:
        user, _, host_port = ssh_target.partition("@")
        ssh_user = user
        host_only, _, port = host_port.partition(":")
        host = host_only or host
        ssh_port = int(port) if port else 22

    # CheckContext only exposes ssh_key_path (no password field) — mirror
    # that. For password-only engagements the runner falls back to the
    # SSHPASS env var, which matches how the deterministic Phase 2 checks
    # already authenticate.
    if ssh_password:
        os.environ.setdefault("SSHPASS", ssh_password)
    ctx = CheckContext(
        host=host,
        ssh_user=ssh_user,
        ssh_key_path=ssh_key or "",
        ssh_port=ssh_port,
    )

    all_results = run_all(ctx)
    all_dicts = [r.to_json_reproducible() if hasattr(r, "to_json_reproducible") else r.__dict__ for r in all_results]

    # Bucket results by their registered framework. Each Check carries
    # a `frameworks` attribute listing the regulations it maps to.
    check_frameworks: dict[str, set[str]] = {}
    for check in registered_checks():
        fws = getattr(check, "frameworks", None) or [getattr(check, "framework", "pci_dss")]
        check_frameworks[check.control_id] = {fw.lower() for fw in fws}

    wanted = {fw.lower() for fw in frameworks}
    out: dict[str, list[dict]] = {fw: [] for fw in wanted}
    for r in all_dicts:
        control_id = r.get("control_id", "")
        result_fws = check_frameworks.get(control_id, set())
        for fw in wanted:
            if fw in result_fws or not result_fws:
                out[fw].append(r)
    # Drop frameworks with no results so the PDF renderer's
    # "must contain at least one framework" guard doesn't trip.
    return {fw: lst for fw, lst in out.items() if lst}


# Match any fenced JSON block (array or object). The agent may emit:
#   1. ```json [ ... ]```            → bare array of findings
#   2. ```json { "findings": [...] }```  → object with findings key + summary
#   3. raw JSON without fences
_AGENT_JSON_FENCE_RE = re.compile(
    r"```(?:json)?\s*([\[{].*?[\]}])\s*```",
    re.DOTALL,
)


def _parse_agent_findings(text: str, *, target_host: str) -> list[Finding]:
    """Extract structured findings from the agent's final output.

    The deepening preamble asks the agent for `{"summary": ..., "findings": [...]}`
    wrapped in a ```json``` fence. We also accept a bare array of findings,
    and raw JSON without fences. Items missing required fields are skipped
    rather than failing the whole engagement.
    """
    if not text:
        return []
    import json

    candidates: list[str] = []
    for m in _AGENT_JSON_FENCE_RE.finditer(text):
        candidates.append(m.group(1))
    # Fallback: bare JSON object/array starting at the first '[' or '{'
    if not candidates:
        i = min(
            (p for p in (text.find("["), text.find("{")) if p >= 0),
            default=-1,
        )
        if i >= 0:
            candidates.append(text[i:])

    out: list[Finding] = []
    for raw in candidates:
        try:
            parsed = json.loads(raw)
        except Exception:
            continue
        # Normalise: an object with a `findings` array, OR a bare array.
        if isinstance(parsed, dict):
            items = parsed.get("findings", [])
        elif isinstance(parsed, list):
            items = parsed
        else:
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "")).upper()
            if sev not in _SEV_RANK:
                continue
            msg = str(item.get("message") or item.get("finding") or "").strip()
            if not msg:
                continue
            out.append(
                Finding(
                    cwe=str(item.get("cwe", "CWE-0")),
                    severity=sev,
                    host=str(item.get("host", target_host)),
                    rule_id=str(item.get("rule_id", "agent-finding")),
                    message=msg,
                    evidence=str(item.get("evidence", ""))[:800],
                    remediation=str(item.get("remediation", "")),
                    severity_rank=_SEV_RANK[sev],
                )
            )
        if out:
            break
    return out


def _invoke_agent_deepening(
    console,
    *,
    target: str,
    scope: str,
    findings: list[Finding],
    families: list[str] | None = None,
) -> tuple[list[str], list[Finding]]:
    """Spin up the unified Kryon agent for one deep-dive turn.

    Returns (observations, new_findings). The agent is asked to emit
    structured JSON findings; we parse the fenced block and convert
    each item to a Finding. Failures are non-fatal — deterministic
    Phase 2 + Phase 2b output is the authoritative surface and the
    agent contributes depth, not correctness.

    F85.D — when `families` is supplied (the result of Phase 1 device
    detection) we hot-swap the agent's skills via
    ``update_agent_skills(agent, ...)`` so the LLM gets skills matched
    against the detected target profile instead of the generic ones
    chosen at agent construction time. Example: detecting a FortiGate
    swaps recon-scout out for fortigate-audit before Phase 2c runs.
    """
    try:
        from kryon.agents import get_agent_by_name
        from kryon.sdk.agents.run import Runner
    except Exception as exc:  # pragma: no cover — dependency missing
        console.print(f"  [dim]agent deepening skipped: {exc}[/dim]")
        return [], []

    os.environ["KRYON_AGENT_TYPE"] = "kryon"
    try:
        agent = get_agent_by_name("kryon", agent_id="ENGAGE")
    except Exception as exc:  # pragma: no cover — runtime only
        console.print(f"  [yellow]agent load failed: {exc}[/yellow]")
        return [], []

    # F85.D — Mid-engagement skill swap. Build a target profile from
    # the detected families and re-rank skills. Done in a try/except
    # so that any failure here falls back to whatever skills the agent
    # was built with — never block the engagement on a swap miss.
    if families:
        try:
            from kryon.skills.loader import SkillLoader
            from kryon.skills.unified_agent import update_agent_skills

            loader = getattr(agent, "_skill_loader", None) or SkillLoader()
            # families like "proxmox", "fortigate", "linux", "windows_ad"
            # come from `_detect_device_families`. We feed them as both
            # tech hints (so triggers matching `tech: ["proxmox"]` fire)
            # and as keywords in the user intent string (so triggers
            # matching `keywords: ["fortigate"]` fire too).
            profile = {"tech": list(families)}
            intent = " ".join(families) + " audit"
            new_skills = loader.match(profile=profile, user_msg=intent)
            if new_skills:
                update_agent_skills(agent, new_skills)
                console.print(f"  [dim]skills swapped: {[s.name for s in new_skills][:5]} (families={families})[/dim]")
        except Exception as exc:  # pragma: no cover — runtime only
            console.print(f"  [yellow]skill swap skipped: {exc}[/yellow]")

    preamble = (
        f"Ya se ejecutó un barrido determinista contra {target} (scope: "
        f"{scope}) y hay {len(findings)} hallazgos. Revisa los servicios "
        "abiertos y confirma o extiende la superficie de riesgo. "
        "\n\n"
        "Al terminar tu investigación, DEVUELVE un objeto JSON con dos "
        "campos: `summary` (string narrativo corto) y `findings` (array "
        "de nuevos hallazgos NO repetidos de los deterministas). "
        "Cada finding tiene: cwe, severity (CRITICAL/HIGH/MEDIUM/LOW), "
        "host, rule_id (snake_case), message (una línea), evidence "
        "(extracto de salida real), remediation (una frase). "
        "Envuelve el array de findings dentro de un bloque ```json … ``` "
        "para que el orquestador pueda parsearlo."
    )
    summary_lines: list[str] = []
    new_findings: list[Finding] = []
    try:
        import asyncio

        # Max turns is tunable via KRYON_AGENT_MAX_TURNS so that pilots
        # against real targets (where the agent needs many SSH-based
        # checks) can extend it without code changes. Default 4 stays
        # because the engage demo flow expects a quick deepening, not
        # a full audit replacement.
        _agent_max = int(os.environ.get("KRYON_AGENT_MAX_TURNS", "4"))

        async def _one_shot() -> str:
            result = await Runner.run(agent, preamble, max_turns=_agent_max)
            return getattr(result, "final_output", "") or ""

        text = asyncio.run(_one_shot())
        if text:
            summary_lines.append(text.strip())
            new_findings = _parse_agent_findings(text, target_host=target)
    except Exception as exc:  # pragma: no cover — runtime only
        console.print(f"  [yellow]agent turn failed: {exc}[/yellow]")
    return summary_lines, new_findings


# -----------------------------------------------------------------------------
# Phase 2c' (F85.F) — orchestrated multi-phase engagement
# -----------------------------------------------------------------------------


_PHASE_PREAMBLES: dict[str, str] = {
    "recon": (
        "Phase: reconnaissance. The target is {target} (scope: {scope}). "
        "Phase 1 nmap already ran — current findings: {findings_count}. "
        "Detected device families: {families}. Use whatweb / nikto / "
        "nuclei to deepen the service inventory. Report new evidence "
        "as structured JSON findings (cwe, severity, host, rule_id, "
        "message, evidence, remediation)."
    ),
    "proxmox_audit": (
        "Phase: Proxmox VE deep-audit. Target {target}. The compliance "
        "runner already ran the deterministic PVE-* checks; your job "
        "is to chase non-deterministic risks: pveproxy reverse-proxy "
        "configuration, root@pam vs root@pve hygiene, qemu agent "
        "exposure, weak TLS ciphers on 8006, exposed API tokens. "
        "Emit JSON findings."
    ),
    "fortigate_audit": (
        "Phase: FortiGate deep-audit. Target {target}. The FGT-* "
        "deterministic checks already ran; chase: SSL-VPN portal "
        "TLS configuration, web admin idle timeouts, log forwarding "
        "destinations, license expiry, IPS/AV signature freshness. "
        "Emit JSON findings."
    ),
    "ad_recon": (
        "Phase: Active Directory enumeration. Target {target}. Run "
        "ldapsearch / kerberos enumeration / SMB null-session probes "
        "(NON-EXPLOITATIVE — read-only enumeration only). Report "
        "domain controllers, trust relationships, weak Kerberos "
        "encryption, exposed services. Emit JSON findings."
    ),
    "vuln_scan": (
        "Phase: vulnerability assessment. Target {target}. Current "
        "findings ({findings_count}): {findings_summary}. Cross-check "
        "with public CVE databases, run nuclei templates against the "
        "open ports, and propose remediation. Emit JSON findings for "
        "any NEW vulnerabilities not in the deterministic surface."
    ),
    "reporting": (
        "Phase: reporting. Target {target}. {findings_count} findings "
        "accumulated. Write a 3-paragraph executive summary in Spanish "
        "for a non-technical bank manager: (1) critical risks and "
        "business impact, (2) patterns and tendencies, (3) "
        "prioritised recommendation. NO new findings — narrative only."
    ),
}


def _phase_preamble(phase_name: str, *, target: str, scope: str, families: list[str], findings: list[Finding]) -> str:
    """Render the per-phase LLM preamble. Falls back to a generic
    template if the phase is unknown (e.g., custom phases injected by
    extended adapt_plan rules)."""
    template = _PHASE_PREAMBLES.get(
        phase_name,
        "Phase: {phase}. Target {target}. Current findings: "
        "{findings_count}. Investigate and emit structured JSON "
        "findings if you discover anything new.",
    )
    findings_summary = "; ".join(f"{f.rule_id} ({f.severity})" for f in findings[:5]) or "none yet"
    return template.format(
        phase=phase_name,
        target=target,
        scope=scope,
        families=", ".join(families) if families else "none detected",
        findings_count=len(findings),
        findings_summary=findings_summary,
    )


def _invoke_orchestrated_engagement(
    console,
    *,
    target: str,
    scope: str,
    findings: list[Finding],
    families: list[str],
) -> tuple[list[str], list[Finding]]:
    """F85.F — Orchestrated multi-phase agent invocation.

    Replacement for ``_invoke_agent_deepening`` activated via the
    ``--orchestrated`` CLI flag. Where the legacy helper invokes a
    single ``Runner.run(max_turns=4)``, this version:

    1. Builds a ``PentestPlan`` via ``PentestPlanner.generate_plan``.
    2. Pre-adapts the plan via ``adapt_plan_for_families`` so detected
       devices (proxmox, fortigate, unifi, windows_ad) get dedicated
       audit phases injected.
    3. Walks the plan phase-by-phase. Each phase runs as a separate
       ``Runner.run`` with a phase-specific preamble and skill set.
    4. After each phase: re-applies ``adapt_plan(plan, findings)`` so
       evidence from earlier phases can grow or skip downstream
       phases (LangChain plan-and-execute pattern).
    5. Honors KRYON_MAX_TURNS / KRYON_PRICE_LIMIT globally (the
       StuckDetector + budget hardening from F85.B/E apply per-phase
       because each phase is a separate ``Runner.run``).

    Failures inside any phase are non-fatal — the failing phase is
    skipped and the orchestrator continues. Deterministic Phase 2/2b
    output remains authoritative; the orchestrator only adds depth.
    """
    try:
        from kryon.agents import get_agent_by_name
        from kryon.sdk.agents.run import Runner
        from kryon.tools.autonomous.pentest_planner import PentestPlanner, PhaseStatus
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]orchestrated path skipped: {exc}[/dim]")
        return [], []

    os.environ["KRYON_AGENT_TYPE"] = "kryon"
    try:
        agent = get_agent_by_name("kryon", agent_id="ENGAGE")
    except Exception as exc:  # pragma: no cover
        console.print(f"  [yellow]agent load failed: {exc}[/yellow]")
        return [], []

    planner = PentestPlanner()
    plan = planner.generate_plan(scope=[target], profile="standard")
    plan = planner.adapt_plan_for_families(plan, families)
    plan = planner.adapt_plan(plan, findings)

    console.print(f"  [dim]plan: {len(plan.phases)} phases ({', '.join(p.name for p in plan.phases)})[/dim]")

    summary_lines: list[str] = []
    new_findings: list[Finding] = []

    import asyncio

    async def _run_phase(phase) -> str:
        max_turns = int(os.environ.get("KRYON_AGENT_MAX_TURNS", str(phase.max_turns)))
        preamble = _phase_preamble(
            phase.name,
            target=target,
            scope=scope,
            families=families,
            findings=findings + new_findings,
        )
        result = await Runner.run(agent, preamble, max_turns=max_turns)
        return getattr(result, "final_output", "") or ""

    for phase in plan.phases:
        if phase.status != PhaseStatus.PENDING:
            console.print(f"  [dim]skipped phase '{phase.name}' (status={phase.status.value})[/dim]")
            continue
        phase.status = PhaseStatus.RUNNING
        phase.findings_before = len(findings) + len(new_findings)
        try:
            console.print(f"  [cyan]▸[/cyan] phase: {phase.name}")
            text = asyncio.run(_run_phase(phase))
        except Exception as exc:  # pragma: no cover
            console.print(f"  [yellow]phase '{phase.name}' failed: {exc}[/yellow]")
            phase.status = PhaseStatus.FAILED
            continue
        if text:
            summary_lines.append(f"[{phase.name}] {text.strip()[:500]}")
            parsed = _parse_agent_findings(text, target_host=target)
            new_findings.extend(parsed)
        phase.status = PhaseStatus.COMPLETED
        phase.findings_after = len(findings) + len(new_findings)
        # Re-adapt the plan with the new findings so downstream phases
        # can react to evidence discovered just now.
        plan = planner.adapt_plan(plan, findings + new_findings)

    return summary_lines, new_findings


# -----------------------------------------------------------------------------
# Phase 2b' — device-family deterministic compliance checks
# -----------------------------------------------------------------------------

# Mapping: family-name → (import path, control_id prefixes, pretty-name).
# `control_id_prefixes` is a tuple so families with non-uniform numbering
# (CIS section_*, where control_ids are "2.2.7", "6.3.3", etc) still get
# filtered cleanly. Adding a new family is one row + an explicit-import
# `__init__.py` on the corresponding check package.
_DEVICE_FAMILIES: list[tuple[str, list[str], tuple[str, ...], str]] = [
    ("proxmox", ["kryon.compliance.checks.proxmox"], ("PVE-",), "Proxmox VE"),
    ("fortigate", ["kryon.compliance.checks.fortigate"], ("FGT-",), "FortiGate"),
    (
        "linux",
        [
            "kryon.compliance.checks.section_2",
            "kryon.compliance.checks.section_6",
            "kryon.compliance.checks.section_8",
            "kryon.compliance.checks.section_10",
        ],
        ("2.", "6.", "8.", "10."),  # CIS Linux uses numeric dotted ids
        "Linux CIS",
    ),
    ("windows_ad", ["kryon.compliance.checks.active_directory"], ("AD-",), "Windows AD"),
    # ("unifi", ["kryon.compliance.checks.unifi"], ("UNF-",), "UniFi"),  # ready when tested
]


def _detect_device_families(services: list[DiscoveredService]) -> list[str]:
    """Heuristic: classify a target into one or more device families based
    on banners and canonical management ports. Returns a list of family
    ids (e.g. ['proxmox', 'linux'] — many real targets match more than
    one because a Proxmox host IS a Linux server too).
    """
    families: list[str] = []

    def _add(fam: str) -> None:
        if fam not in families:
            families.append(fam)

    has_ssh = False
    for s in services:
        product = (s.product or "").lower()
        # Proxmox VE
        if "proxmox" in product or s.port in (8006, 3128):
            _add("proxmox")
        # FortiGate
        if "fortigate" in product or "fortinet" in product or "fortios" in product or s.port in (10443, 8443):
            _add("fortigate")
        # Windows AD (LDAP 389, LDAPS 636, Kerberos 88, SMB 445, RPC EPM 135)
        if s.port in (88, 135, 389, 445, 636, 3268, 3269):
            _add("windows_ad")
        # Track SSH presence — Linux CIS checks need SSH access. We only
        # tag the target as 'linux' when SSH is open AND the banner does
        # NOT scream "FortiOS" / "Cisco IOS" / "PVE" (those have their
        # own family above; running generic CIS Linux against them
        # would emit noisy false positives).
        if s.port == 22 and s.state == "open":
            has_ssh = True

    if has_ssh:
        # Only auto-add 'linux' when there's no Forti / Cisco / similar
        # appliance signature already in the family list. Proxmox IS
        # Linux underneath so we DO want CIS Linux checks alongside PVE.
        appliance_families = {"fortigate"}
        if not any(f in appliance_families for f in families):
            _add("linux")

    return families


def _run_device_compliance(
    console,
    *,
    family: str,
    host: str,
    ssh_target: str | None,
    ssh_key: str | None,
) -> list[Finding]:
    """Run the deterministic checks for a specific device family via the
    compliance runner. Promotes FAIL/ERROR verdicts to engage Findings.

    `family` must be a key in `_DEVICE_FAMILIES`. Silent skip when the
    package can't be imported (fresh checkout). Phase 2 deterministic +
    agent dive remain the fallback surfaces.
    """
    family_row = next((row for row in _DEVICE_FAMILIES if row[0] == family), None)
    if family_row is None:
        console.print(f"  [dim]unknown device family: {family}[/dim]")
        return []
    _, import_paths, prefixes, pretty_name = family_row

    try:
        import importlib

        for path in import_paths:
            importlib.import_module(path)  # side-effect registers checks
        from kryon.compliance.checks.base import CheckContext
        from kryon.compliance.runner import run_all
    except Exception as exc:
        console.print(f"  [dim]{pretty_name} compliance skipped: {exc}[/dim]")
        return []

    ssh_user = "root"
    ssh_port = 22
    target_host = host
    if ssh_target:
        user, _, host_port = ssh_target.partition("@")
        ssh_user = user or "root"
        host_only, _, port = host_port.partition(":")
        target_host = host_only or host
        ssh_port = int(port) if port else 22

    # FortiGate audits typically use a dedicated non-root admin (`admin`,
    # `audit`, etc); accept whatever the operator passed in --ssh.
    ctx = CheckContext(
        host=target_host,
        ssh_user=ssh_user,
        ssh_key_path=ssh_key or "",
        ssh_port=ssh_port,
        transport="ssh",
    )

    # Filter results to the family's control_id prefixes so we never
    # bleed other frameworks (e.g. a prior _run_compliance pass) into
    # engage's findings table. CIS Linux uses numeric dotted ids
    # ("2.2.7"), so `prefixes` is a tuple.
    all_results = run_all(ctx)
    family_results = [r for r in all_results if any(r.control_id.upper().startswith(p.upper()) for p in prefixes)]

    findings: list[Finding] = []
    for r in family_results:
        if r.verdict not in ("FAIL", "ERROR"):
            continue
        sev = (r.severity or "MEDIUM").upper()
        if sev not in _SEV_RANK:
            sev = "MEDIUM"
        evidence = (r.evidence_stdout or r.evidence_stderr or "")[:600]
        findings.append(
            Finding(
                cwe="CWE-0",  # device-specific checks don't map 1:1 to CWE
                severity=sev,
                host=f"{ssh_user}@{target_host}",
                rule_id=r.control_id,
                message=r.control_title or r.control_id,
                evidence=evidence,
                remediation=(r.remediation_static or "")[:400],
                target_host=f"{ssh_user}@{target_host}",
                severity_rank=_SEV_RANK[sev],
            )
        )
    if findings:
        # `prefixes[0].rstrip('-')` gives us a nice short tag — "PVE",
        # "FGT", "2.", "AD" — for the operator banner.
        short_tag = prefixes[0].rstrip("-").rstrip(".")
        console.print(
            f"  [green]{pretty_name} compliance:[/green] {len(findings)} FAIL/ERROR "
            f"(de {len(family_results)} controles {short_tag})"
        )
    return findings


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

    # F85.B — Budget hardening: propagate CLI overrides into env so the
    # CostTracker (which reads KRYON_PRICE_LIMIT lazily) and the SDK
    # runner (which reads KRYON_MAX_TURNS at import) honor them. Only
    # write when the operator passed an explicit value — env defaults
    # remain authoritative otherwise.
    if args.max_turns is not None:
        os.environ["KRYON_MAX_TURNS"] = str(args.max_turns)
    if args.max_cost is not None:
        os.environ["KRYON_PRICE_LIMIT"] = str(args.max_cost)

    target = args.target
    scope = args.scope or target
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    engagement_id = args.engagement_id or (f"engagement-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}")

    # Security hygiene: prefer `SSHPASS` env over --ssh-password argv.
    # Passing the password as a CLI argument to `kryon engage` leaves
    # the plaintext in /proc/<pid>/cmdline of the Kryon process itself
    # (visible to every local process). Warn if that's how we got it;
    # fall back to SSHPASS env when the flag is absent.
    pwd_from_argv = bool(args.ssh_password)
    if not args.ssh_password and os.environ.get("SSHPASS"):
        args.ssh_password = os.environ["SSHPASS"]
    if pwd_from_argv:
        console.print(
            "[yellow]⚠  --ssh-password in argv is visible in /proc. "
            "Prefer: `export SSHPASS=... && kryon engage ...` (drop the flag) "
            "or use an SSH key.[/yellow]"
        )

    # --- Phase 1: discovery -----------------------------------------------
    _banner(console, f"Fase 1 — descubrimiento ({target})")
    xml = _run_nmap(target, timeout_s=args.nmap_timeout)
    services = _parse_nmap_xml(xml, target)
    open_svcs = [s for s in services if s.state == "open"]
    console.print(f"  [green]{len(open_svcs)}[/green] puertos abiertos en {target}")
    for s in open_svcs[:10]:
        console.print(f"    {s.port:>5}/{s.state}  {s.service} {s.product or ''} {s.version or ''}")

    # --- Phase 2: service checks ------------------------------------------
    _banner(console, "Fase 2 — evaluación por servicio")
    findings: list[Finding] = []
    for svc in open_svcs:
        if svc.service in ("http", "http-proxy", "https") or svc.port in (80, 443, 8080, 8443):
            findings.extend(_check_http(svc))
        if svc.service == "ssh" or svc.port == 22 or svc.port == 2222:
            findings.extend(_check_ssh(svc, args.ssh, args.ssh_password))
        if svc.service in ("mysql", "postgresql", "mongodb", "redis") or svc.port in (3306, 33060, 5432, 27017, 6379):
            findings.extend(_check_mysql(svc))

    findings.sort(key=lambda f: f.severity_rank)
    console.print(f"  [yellow]{len(findings)}[/yellow] hallazgos detectados")

    # --- Phase 2b: compliance sweep (F77.A) -------------------------------
    framework_results: dict[str, list[dict]] = {}
    frameworks = [fw.strip().lower() for fw in (args.framework or "").split(",") if fw.strip()]
    if frameworks:
        _banner(console, f"Fase 2b — compliance ({', '.join(frameworks)})")
        try:
            framework_results = _run_compliance(
                frameworks,
                host=target,
                ssh_target=args.ssh,
                ssh_password=args.ssh_password,
                ssh_key=args.ssh_key,
            )
            for fw, results in framework_results.items():
                fail = sum(1 for r in results if r.get("verdict") == "FAIL")
                console.print(f"  [cyan]{fw}[/cyan]: {len(results)} controls, [red]{fail} FAIL[/red]")
        except Exception as exc:
            console.print(f"  [red]compliance runner failed:[/red] {exc}")

    # --- Phase 2b' — device-family deterministic compliance --------------
    # Auto-detect which device family/families the target belongs to and
    # invoke the matching `c_<fam>_*` compliance checks. Promotes FAIL /
    # ERROR verdicts to engagement findings. Currently covers Proxmox VE
    # and FortiGate; adding a family means editing `_DEVICE_FAMILIES` and
    # making sure its check package `__init__.py` imports its submodules.
    detected_families = _detect_device_families(services)
    for fam in detected_families:
        _banner(console, f"Fase 2b' — {fam} deterministic checks")
        fam_findings = _run_device_compliance(
            console,
            family=fam,
            host=target,
            ssh_target=args.ssh,
            ssh_key=args.ssh_key,
        )
        if fam_findings:
            findings.extend(fam_findings)
            findings.sort(key=lambda f: (f.severity_rank, f.host, f.rule_id))

    # --- Phase 2c: optional agent deepening (F77.A / F85.D / F85.F) -------
    agent_observations: list[str] = []
    orchestrated = args.orchestrated or os.environ.get("KRYON_ORCHESTRATED", "").lower() in {"1", "true", "yes"}
    if args.use_agent or os.environ.get("KRYON_ENGAGE_AGENT", "").lower() in {"1", "true", "yes"} or orchestrated:
        if orchestrated:
            _banner(console, "Fase 2c' — orquestador multi-fase (F85.F)")
            agent_observations, agent_findings = _invoke_orchestrated_engagement(
                console,
                target=target,
                scope=scope,
                findings=findings,
                families=detected_families,
            )
        else:
            _banner(console, "Fase 2c — agente Kryon (deep-dive)")
            # F85.D — pass detected_families so the agent's skill set
            # gets re-ranked against the actual target profile before
            # the LLM turn (mid-engagement skill swap).
            agent_observations, agent_findings = _invoke_agent_deepening(
                console,
                target=target,
                scope=scope,
                findings=findings,
                families=detected_families,
            )
        if agent_findings:
            findings.extend(agent_findings)
            findings.sort(key=lambda f: (f.severity_rank, f.host, f.rule_id))
            console.print(f"  [green]agent findings:[/green] +{len(agent_findings)} estructurados desde el LLM")
        if agent_observations:
            console.print(f"  [green]✓[/green] agente produjo {len(agent_observations)} observaciones")

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
                ApprovalRequest,
                ApprovalResult,
                ProposedAction,
                Severity,
                ask_approval,
            )

            sev_map = {
                "critical": Severity.DESTRUCTIVE,
                "high": Severity.MODIFY,
                "medium": Severity.MODIFY,
                "low": Severity.READ,
                "info": Severity.READ,
            }
            req = ApprovalRequest(
                title=f"Aplicar {len(actions)} correcciones en {args.ssh}",
                subtitle=f"Engagement: {engagement_id}",
                actions=[
                    ProposedAction(
                        command=a["command"],
                        purpose=a["purpose"],
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
                verdict = ask_approval(req, console=console, default=ApprovalResult.NO)

            if verdict == ApprovalResult.YES:
                for a in actions:
                    user_host, port = _parse_ssh_arg(a["target_host"])
                    user, _, host = user_host.partition("@")
                    base = [
                        "ssh",
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-p",
                        port,
                        f"{user}@{host}",
                    ]
                    # SSHPASS env instead of `-p <password>` — argv stays
                    # clean for anyone watching `ps auxf`.
                    env = None
                    if args.ssh_password:
                        env = {**os.environ, "SSHPASS": args.ssh_password}
                        base = ["sshpass", "-e"] + base
                    console.print(f"  [dim]$[/dim] {a['command'][:90]}")
                    try:
                        r = subprocess.run(
                            base + [a["command"]],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            check=False,
                            env=env,
                        )
                        if r.returncode == 0:
                            console.print("  [green]✓[/green] applied")
                            applied_findings.append(a["purpose"])
                        else:
                            console.print(f"  [red]✗[/red] exit {r.returncode}: {r.stderr[:120]}")
                    except Exception as exc:
                        console.print(f"  [red]✗[/red] {exc}")
            else:
                console.print(f"[yellow]veredicto: {verdict.value} — nada aplicado[/yellow]")
        else:
            console.print("  [dim]sin acciones con comando de remediación[/dim]")

    # --- Phase 5: re-audit (when remediation applied) ---------------------
    if applied_findings and not args.skip_reaudit:
        _banner(console, "Fase 5 — re-auditoría")
        xml2 = _run_nmap(target, timeout_s=args.nmap_timeout)
        services2 = _parse_nmap_xml(xml2, target)
        console.print(
            f"  [dim]re-scan:[/dim] {sum(1 for s in services2 if s.state == 'open')} puertos abiertos tras aplicar"
        )

    # --- Phase 6: report --------------------------------------------------
    _banner(console, "Fase 6 — reporte")
    findings_dict = [
        {
            **{k: v for k, v in asdict(f).items() if k != "severity_rank"},
        }
        for f in findings
    ]

    paths: dict[str, str] = {}
    if framework_results:
        # Multi-framework consolidated PDF (F44) — the banking-grade output.
        from kryon.reporting.multi_framework_pdf import (
            render_multi_framework_html,
            render_multi_framework_pdf,
        )

        html_path = out_dir / f"kryon-{engagement_id}-consolidated.html"
        pdf_path = out_dir / f"kryon-{engagement_id}-consolidated.pdf"
        html_path.write_text(
            render_multi_framework_html(
                framework_results,
                host=scope,
                client_name=args.client or "",
            ),
            encoding="utf-8",
        )
        paths["html_multi"] = str(html_path)
        try:
            render_multi_framework_pdf(
                framework_results,
                str(pdf_path),
                host=scope,
                client_name=args.client or "",
            )
            paths["pdf_multi"] = str(pdf_path)
        except ImportError as exc:
            console.print(f"  [yellow]PDF skipped — weasyprint unavailable: {exc}[/yellow]")

    # Always emit the demo_report as a secondary deliverable so the
    # deterministic surface is documented even when compliance ran.
    from kryon.reporting.demo_report import render_demo_report

    ctx = {
        "client_name": args.client or "",
        "engagement_id": engagement_id,
        "target_scope": scope,
        "auditor": args.auditor or "SkyVanguard / Kryon",
        "applied": applied_findings,
        "agent_observations": agent_observations,
    }
    demo_paths = render_demo_report(
        findings_dict,
        ctx,
        output_dir=out_dir,
        filename_stem=f"kryon-{engagement_id}",
    )
    paths.update(demo_paths)
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
    p.add_argument(
        "--ssh-password",
        help=("SSH password (passed to sshpass via SSHPASS env, NOT as argv). Prefer --ssh-key for production."),
    )
    p.add_argument("--out", default="./kryon-reports", help="output directory for the report")
    p.add_argument("--client", default="", help="client name for the report header")
    p.add_argument("--engagement-id", default="", help="engagement identifier")
    p.add_argument("--auditor", default="", help="auditor name (default: SkyVanguard / Kryon)")
    p.add_argument("--dry-run-only", action="store_true", help="skip remediation even if --ssh provided")
    p.add_argument("--auto-approve", action="store_true", help="skip approval prompt (lab / demo only — NEVER prod)")
    p.add_argument("--nmap-timeout", type=int, default=600, help="nmap wall-clock timeout in seconds (default: 600)")
    p.add_argument(
        "--framework",
        default="",
        help="comma-separated compliance frameworks to audit "
        "(e.g. 'pci_dss,bcp_py,swift_csp'). Produces the "
        "multi-framework consolidated PDF.",
    )
    p.add_argument(
        "--use-agent",
        action="store_true",
        help="invoke the unified Kryon agent after Phase 2 to deepen coverage (KRYON_ENGAGE_AGENT env also works)",
    )
    p.add_argument(
        "--orchestrated",
        action="store_true",
        help="F85.F — invoke PentestPlanner multi-phase orchestration instead of "
        "a single-shot LLM dive. Each detected device family gets a "
        "dedicated audit phase (proxmox/fortigate/unifi/AD); plan adapts "
        "between phases based on accumulated findings. KRYON_ORCHESTRATED "
        "env var also works. Implies --use-agent.",
    )
    p.add_argument("--ssh-key", default="", help="SSH private key path for compliance runner")
    p.add_argument("--skip-reaudit", action="store_true", help="skip the post-remediation re-scan (Phase 5)")
    # F85.B — Budget hardening. Both flags are also readable from env
    # (KRYON_MAX_TURNS, KRYON_PRICE_LIMIT) so containerised runs can be
    # capped without touching the CLI invocation.
    p.add_argument(
        "--max-turns",
        type=int,
        default=None,
        help="hard cap on LLM turns per run (default: 40 from KRYON_MAX_TURNS). "
        "Prevents a stuck agent from looping until the API key runs out.",
    )
    p.add_argument(
        "--max-cost",
        type=float,
        default=None,
        help="hard cap on USD spent per run (default: 5.0 from KRYON_PRICE_LIMIT). "
        "CostTracker aborts the chat-completions call path when exceeded.",
    )
    # F85.H — Cover page + branding flags. Empty defaults keep current
    # demo/CI outputs visually identical (only triggered when set).
    p.add_argument(
        "--brand-logo",
        default="",
        help="path to client logo (PNG/JPG/SVG) for the report cover. "
        "Empty falls back to client_name as text placeholder.",
    )
    p.add_argument(
        "--brand-color",
        default="",
        help='accent color hex for the report cover, e.g. "#0070d2". Empty keeps the Kryon default blue.',
    )
    p.add_argument(
        "--classification",
        default="INTERNAL",
        choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
        help="document classification banner shown on the cover and footer.",
    )
    return p
