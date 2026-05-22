"""F203.A — `kryon investigate` entry point (open-ended ReAct loop).

A diferencia de `kryon engage` (que tiene fases fijas 1-6 con target IP
+ scope rígido), `investigate` deja al agent decidir qué hacer.

Casos de uso:
    kryon investigate "audita la seguridad de https://eaula.ing.una.py"
    kryon investigate "qué CVEs aplican a nginx 1.18"
    kryon investigate ./codigo/   (SAST exploratorio)
    kryon investigate --url https://target.example.com/

Diseño:
- El prompt del usuario va directo al unified_agent.
- Skills se cargan dinámicamente vía SkillLoader.match(user_msg=prompt).
- web_fetch_smart está siempre disponible (F203.B).
- max_turns alto (default 30) — el agent decide cuándo parar.
- Sin fases discrete — un solo loop hasta que el agent emite "done"
  o se acaba el budget.

Banca-safe contract:
- Por default, NO ejecuta tools activas contra targets externos.
- KRYON_INVESTIGATE_ACTIVE=1 habilita active probing (nmap/nuclei/etc).
- Default mode = passive: solo web_fetch_smart + duckduckgo_search +
  knowledge base lookups.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _is_url(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def _is_local_path(s: str) -> bool:
    return Path(s).expanduser().exists()


def _classify_intent(prompt: str) -> dict[str, Any]:
    """Heuristic: detect what kind of investigation the user wants.

    Returns hints for skill matching + tool prefiltering.
    """
    lower = prompt.lower()
    hints: dict[str, Any] = {"keywords": [], "mode": "general"}

    # URL detection
    urls: list[str] = []
    for word in prompt.split():
        if _is_url(word):
            urls.append(word.rstrip("),.;"))
    if urls:
        hints["urls"] = urls
        hints["mode"] = "web_audit"
        hints["keywords"].extend([
            "webapp", "web vulnerability", "http",
            "cwe-79", "cwe-89", "cwe-352", "cwe-22", "cwe-918",
        ])

    # Code path detection
    for word in prompt.split():
        if _is_local_path(word) and Path(word).is_dir():
            hints["mode"] = "code_sast"
            hints["code_path"] = word
            hints["keywords"].extend(["sast", "code review", "source code"])
            break

    # Topic-based hints
    if "cve" in lower or "vulnerability" in lower or "exploit" in lower:
        hints["keywords"].extend(["cve", "vulnerability", "exploit"])
    if "moodle" in lower:
        hints["keywords"].extend(["moodle", "lms", "webapp"])
    if "wordpress" in lower or "wp-" in lower:
        hints["keywords"].extend(["wordpress", "wp", "webapp"])
    if any(k in lower for k in ("login", "auth", "jwt", "session")):
        hints["keywords"].extend(["auth", "authentication", "cwe-287"])
    if any(k in lower for k in ("sql", "sqli", "injection")):
        hints["keywords"].extend(["sqli", "sql injection", "cwe-89"])
    if any(k in lower for k in ("xss", "cross-site")):
        hints["keywords"].extend(["xss", "cwe-79"])

    return hints


def _build_investigate_prompt(user_prompt: str, hints: dict[str, Any], active: bool) -> str:
    """Compose the system context the agent receives at turn 1."""
    mode = hints.get("mode", "general")
    safety = (
        "🟢 PASSIVE MODE — Solo usa: web_fetch_smart (HTTP GET), "
        "duckduckgo_search, query_knowledge_base, recall_similar_experiences, "
        "search_vulnerabilities. NO ejecutes nmap, nuclei, sqlmap, nikto, "
        "ni ninguna tool activa contra targets externos sin autorización.\n"
        if not active
        else "🔴 ACTIVE MODE — Tools activas autorizadas (nmap/nuclei/sqlmap). "
        "Validar que hay autorización escrita ANTES de probar.\n"
    )

    urls_block = ""
    if hints.get("urls"):
        urls_block = "\nURLs detectadas en el prompt: " + ", ".join(hints["urls"]) + "\n"

    code_block = ""
    if hints.get("code_path"):
        code_block = f"\nPath local detectado: {hints['code_path']}\n"

    return (
        f"# Investigación abierta\n\n"
        f"**Modo**: {mode}\n\n"
        f"{safety}\n"
        f"## Pedido del operador\n\n"
        f"{user_prompt}\n"
        f"{urls_block}{code_block}\n\n"
        f"## Loop esperado\n\n"
        f"1. **Observar**: cada turn empezá con `web_fetch_smart` o equivalente "
        f"para tener evidencia fresca. NO confíes en conocimiento previo sin verificar.\n"
        f"2. **Reflexionar**: ¿qué aprendí que NO sabía? ¿qué hipótesis sigue abierta?\n"
        f"3. **Decidir**: ¿qué tool siguiente aporta más signal? Si no sabés, "
        f"buscá en knowledge base o web search.\n"
        f"4. **Verificar**: si una tool devuelve algo confuso, repetí con args distintos "
        f"o cross-validar con otra fuente. NO emitas findings basados en una sola señal.\n"
        f"5. **Parar** cuando: (a) el objetivo del operador está cubierto, "
        f"(b) sin authorization explícita para profundizar, o (c) se necesita info externa "
        f"que el operador debe proveer.\n\n"
        f"## Pre-hooks: NO son authoritative (F203.AN)\n\n"
        f"Si recibís un bloque `deterministic_compliance_findings` / "
        f"`sqlmap_multi_endpoint_probe` / `nuclei_*_battery` / `idor_sequential_probe` "
        f"VACÍO o sin findings concretos, **NO interpretes eso como 'target limpio'**. "
        f"Significa que el detector canned NO matcheó las heurísticas curated. "
        f"En ese caso DEBÉS:\n"
        f"  - Continuar con `run_command` manual (curl, sqlmap, nuclei) contra "
        f"    los endpoints específicos del target.\n"
        f"  - Para PortSwigger labs: usar el path del lab + query params del lab "
        f"    (e.g. `?category=Gifts'+OR+1=1--`).\n"
        f"  - Para webapps custom: descubrir endpoints con `web_fetch_smart` + parsing "
        f"    de forms en el HTML.\n"
        f"NUNCA emitas `[]` (findings vacío) sin haber intentado al menos 3 tool calls "
        f"manuales adicionales.\n\n"
        f"Cuando termines, emití un **resumen ejecutivo** con: lo que aprendiste, "
        f"hallazgos preliminares (si aplican), y próximos pasos sugeridos para el operador.\n"
    )


def _safe_call(fn, *args, **kwargs):
    """Invoke a detector defensively — return [] on any error."""
    try:
        r = fn(*args, **kwargs)
    except Exception:  # noqa: BLE001 — defensive; LLM still runs
        return []
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


def _run_deterministic_phase(
    url: str,
    *,
    ssh_user: str = "",
    ssh_password: str = "",
    ssh_key: str = "",
    db_user: str = "",
    db_password: str = "",
    include_dns: bool = False,
    include_smb: bool = False,
) -> list:
    """F203.M/N — Hybrid mode: run deterministic checks BEFORE the LLM agent.

    F203.M (N=0): HTTP/HTTPS + MySQL banner-only checks.
    F203.N.1:    Python http.server exposed + BGP port detect.
    F203.N.2:    SSH deep audit (creds-aware) + MySQL deep audit (F202.W).
    F203.N.3:    DNS battery (zone transfer / chaos / dnssec / open resolver /
                 reverse enum) + SMB anonymous shares — opt-in via flags.

    Skips silently on import/runtime errors — the LLM agent will still run.
    """
    from urllib.parse import urlparse

    try:
        from kryon.cli.engage import (
            DiscoveredService,
            _check_bgp_exposure,
            _check_dns_chaos_leak,
            _check_dns_open_resolver,
            _check_dns_zone_transfer,
            _check_dnssec_validation,
            _check_http,
            _check_http_cookie_flags,
            _check_mysql,
            _check_mysql_deep,
            _check_python_simplehttp_exposed,
            _check_reverse_dns_enum,
            _check_smb_anonymous_shares,
            _check_ssh,
        )
    except ImportError:
        return []

    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = (parsed.scheme or "").lower()
    if not host:
        return []

    port = parsed.port
    if port is None:
        defaults = {
            "https": 443, "http": 80, "ssh": 22, "mysql": 3306,
            "postgres": 5432, "postgresql": 5432, "redis": 6379,
            "mongodb": 27017, "dns": 53, "smb": 445, "cifs": 445,
        }
        port = defaults.get(scheme)
        if port is None:
            return []

    findings: list = []

    # HTTP / HTTPS
    if scheme in ("http", "https") or port in (80, 443, 8080, 8443, 8000, 8888):
        svc = DiscoveredService(
            host=host, port=port, state="open",
            service="https" if scheme == "https" or port == 443 else "http",
        )
        findings.extend(_safe_call(_check_http, svc))
        findings.extend(_safe_call(_check_http_cookie_flags, svc))
        # F203.N.1 — Python http.server directory listing
        findings.extend(_safe_call(_check_python_simplehttp_exposed, svc))

    # SSH — F203.N.2 creds-aware deep audit
    elif scheme == "ssh" or port in (22, 2222):
        svc = DiscoveredService(host=host, port=port, state="open", service="ssh")
        ssh_target = f"{ssh_user}@{host}" if ssh_user else None
        # _check_ssh reads KRYON_SSH_PORT / KRYON_SSH_KEY_PATH from env
        prior_port = os.environ.get("KRYON_SSH_PORT")
        prior_key = os.environ.get("KRYON_SSH_KEY_PATH")
        try:
            if port != 22:
                os.environ["KRYON_SSH_PORT"] = str(port)
            if ssh_key:
                os.environ["KRYON_SSH_KEY_PATH"] = ssh_key
            findings.extend(
                _safe_call(_check_ssh, svc, ssh_target, ssh_password or None)
            )
        finally:
            if prior_port is None:
                os.environ.pop("KRYON_SSH_PORT", None)
            else:
                os.environ["KRYON_SSH_PORT"] = prior_port
            if prior_key is None:
                os.environ.pop("KRYON_SSH_KEY_PATH", None)
            else:
                os.environ["KRYON_SSH_KEY_PATH"] = prior_key

    # MySQL / Postgres / common DB ports
    elif port in (3306, 33060):
        svc = DiscoveredService(host=host, port=port, state="open", service="mysql")
        findings.extend(_safe_call(_check_mysql, svc))
        # F203.N.2 — F202.W deep audit with creds
        if db_user and db_password:
            prior_u = os.environ.get("KRYON_DB_USER")
            prior_p = os.environ.get("KRYON_DB_PASSWORD")
            try:
                os.environ["KRYON_DB_USER"] = db_user
                os.environ["KRYON_DB_PASSWORD"] = db_password
                findings.extend(_safe_call(_check_mysql_deep, svc))
            finally:
                if prior_u is None:
                    os.environ.pop("KRYON_DB_USER", None)
                else:
                    os.environ["KRYON_DB_USER"] = prior_u
                if prior_p is None:
                    os.environ.pop("KRYON_DB_PASSWORD", None)
                else:
                    os.environ["KRYON_DB_PASSWORD"] = prior_p

    elif port in (5432, 27017, 6379, 1433, 1521):
        svc = DiscoveredService(host=host, port=port, state="open", service="database")
        findings.extend(_safe_call(_check_mysql, svc))

    # F203.N.1 — BGP port exposure
    elif port == 179:
        svc = DiscoveredService(host=host, port=179, state="open", service="bgp")
        findings.extend(_safe_call(_check_bgp_exposure, svc))

    # F203.N.3 — DNS opt-in (port 53 OR dns:// scheme)
    if include_dns and (port == 53 or scheme == "dns"):
        svc_dns = DiscoveredService(host=host, port=53, state="open", service="dns")
        for chk in (
            _check_dns_open_resolver,
            _check_dns_zone_transfer,
            _check_dns_chaos_leak,
            _check_dnssec_validation,
            _check_reverse_dns_enum,
        ):
            findings.extend(_safe_call(chk, svc_dns))

    # F203.N.3 — SMB opt-in (port 445 OR smb:// scheme)
    if include_smb and (port == 445 or scheme in ("smb", "cifs")):
        svc_smb = DiscoveredService(host=host, port=445, state="open", service="smb")
        findings.extend(_safe_call(_check_smb_anonymous_shares, svc_smb))

    return findings


def _format_findings_for_prompt(findings: list) -> str:
    """Render Finding list as markdown block to inject into agent prompt."""
    if not findings:
        return ""
    lines = ["", "## 🔬 Deterministic findings ya detectados (F203.M)", ""]
    lines.append(
        "Los siguientes hallazgos YA fueron confirmados por detectores "
        "deterministicos previos al loop ReAct. **NO los repitas en tu "
        "resumen final como si fueran tuyos** — son ground truth confirmado. "
        "Tu trabajo es:"
    )
    lines.append("  1. Reconocerlos como inicio de evidencia")
    lines.append("  2. EXTENDER con findings semánticos que los detectores no ven")
    lines.append("     (e.g. lógica de negocio, control de acceso, info disclosure)")
    lines.append("  3. Validar/contextualizar cada uno con un curl adicional si dudás")
    lines.append("")
    for f in findings:
        cwe = getattr(f, "cwe", "?")
        rule = getattr(f, "rule_id", "?")
        severity = getattr(f, "severity", "?")
        host = getattr(f, "host", "?")
        message = getattr(f, "message", "")
        lines.append(f"- **{cwe}** ({severity}) · `{rule}` · {host}")
        if message:
            lines.append(f"    {message[:200]}")
    lines.append("")
    return "\n".join(lines)


def run_investigate(args: argparse.Namespace) -> int:
    """Main entry point for `kryon investigate`."""
    from rich.console import Console

    console = Console()

    # F203.L — renamed from `prompt` to `query` to avoid dest collision
    # with the parent CLI's `prompt` positional (which is set to None).
    prompt = args.query
    if args.url:
        prompt = (
            f"{prompt} (URL declarada explícitamente: {args.url})"
            if prompt
            else f"Investigá {args.url}"
        )
    if not prompt:
        console.print("[red]error: provide a prompt or --url[/red]")
        return 2

    hints = _classify_intent(prompt)
    active = args.active or os.environ.get("KRYON_INVESTIGATE_ACTIVE", "").lower() in (
        "1", "true", "yes"
    )

    console.print(f"[cyan]▸ Investigate mode:[/cyan] {hints.get('mode', 'general')}")
    if active:
        console.print("[yellow]⚠  ACTIVE mode — tools activas autorizadas[/yellow]")
    else:
        console.print("[green]✓ PASSIVE mode (default banca-safe)[/green]")

    # Load skills based on prompt + hints
    try:
        from kryon.skills.loader import SkillLoader
    except ImportError:
        console.print("[red]SkillLoader unavailable[/red]")
        return 3

    loader = SkillLoader()
    intent = prompt + " " + " ".join(hints.get("keywords", []))
    matched = loader.match(profile={}, user_msg=intent)
    if matched:
        console.print(
            f"[dim]skills loaded: {[s.name for s in matched[:6]]} "
            f"(total={len(matched)})[/dim]"
        )

    # Build agent + run loop
    try:
        from kryon.agents import get_agent_by_name
        from kryon.sdk.agents.run import Runner
        from kryon.sdk.agents.run_config_factory import get_run_config
        from kryon.skills.unified_agent import update_agent_skills
    except ImportError as e:
        console.print(f"[red]agent dependencies missing: {e}[/red]")
        return 4

    os.environ["KRYON_AGENT_TYPE"] = "kryon"
    try:
        agent = get_agent_by_name("kryon", agent_id="INVESTIGATE")
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]agent load failed: {e}[/red]")
        return 5

    if matched:
        try:
            update_agent_skills(agent, matched)
        except Exception as e:  # noqa: BLE001 — best effort
            console.print(f"[yellow]skill swap warning: {e}[/yellow]")

    full_prompt = _build_investigate_prompt(prompt, hints, active=active)

    # F203.M — Hybrid mode: run deterministic checks ANTES del agent, inyectar
    # findings al prompt. Default ON cuando hay URL detectable.
    deterministic_findings: list = []
    if not args.no_hybrid:
        urls_to_check = list(hints.get("urls") or [])
        if args.url and args.url not in urls_to_check:
            urls_to_check.append(args.url)
        for u in urls_to_check:
            df = _run_deterministic_phase(
                u,
                ssh_user=args.ssh_user,
                ssh_password=args.ssh_pass,
                ssh_key=args.ssh_key,
                db_user=args.db_user,
                db_password=args.db_pass,
                include_dns=args.include_dns_checks,
                include_smb=args.include_smb_checks,
            )
            if df:
                deterministic_findings.extend(df)

        if deterministic_findings:
            console.print(
                f"[cyan]🔬 deterministic phase:[/cyan] "
                f"{len(deterministic_findings)} finding(s) detected before agent loop"
            )
            for f in deterministic_findings[:8]:
                console.print(
                    f"  [dim]→ {getattr(f, 'cwe', '?')} {getattr(f, 'rule_id', '?')}[/dim]"
                )
            full_prompt = full_prompt + _format_findings_for_prompt(deterministic_findings)

    max_turns = args.max_turns
    reflect_every = args.reflect_every

    if reflect_every > 0:
        console.print(
            f"[dim]starting ReAct loop with reflection every {reflect_every} turns "
            f"(max_turns={max_turns})[/dim]\n"
        )
    else:
        console.print(f"[dim]starting ReAct loop (max_turns={max_turns}, reflection disabled)[/dim]\n")

    async def _run() -> Any:
        # F203.Z.B — fire skill-declared pre_hooks BEFORE agent run.
        # engage.py invokes maybe_run_pre_hooks via _run_phase (F185-C),
        # but investigate.py was missing this — the F203.V/W/X
        # web-pentest-{sqli,xss,idor}-active skills had pre_hooks that
        # never executed. Now they do.
        agent_input = full_prompt
        try:
            from kryon.skills.pre_hook_integration import maybe_run_pre_hooks
            pre_hook_suffix = await maybe_run_pre_hooks(agent, full_prompt, console)
            if pre_hook_suffix:
                agent_input = full_prompt + pre_hook_suffix
        except Exception as e:  # noqa: BLE001 — pre_hooks must never break the run
            console.print(f"[yellow]pre_hook integration warning: {e}[/yellow]")

        # F203.C — use reflective runner when reflect_every > 0
        if reflect_every > 0:
            from kryon.cli.reflective_runner import run_with_reflection
            return await run_with_reflection(
                agent,
                initial_input=agent_input,
                reflect_every=reflect_every,
                max_total_turns=max_turns,
                run_config=get_run_config(),
            )
        return await Runner.run(
            agent,
            input=agent_input,
            max_turns=max_turns,
            run_config=get_run_config(),
        )

    try:
        result = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted by user[/yellow]")
        return 130
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]agent run failed: {type(e).__name__}: {e}[/red]")
        return 6

    output = getattr(result, "final_output", None) or ""

    # F203.M — Prepend deterministic findings to output so scoreboard
    # (and any downstream CWE-extraction) sees them. The LLM summary may
    # or may not include each CWE in prose — explicit deterministic
    # findings ensure they're in the transcript.
    if deterministic_findings:
        det_block_lines = ["## Hallazgos deterministicos (pre-agent F203.M)"]
        for f in deterministic_findings:
            cwe = getattr(f, "cwe", "?")
            rule = getattr(f, "rule_id", "?")
            severity = getattr(f, "severity", "?")
            host = getattr(f, "host", "?")
            message = getattr(f, "message", "")
            det_block_lines.append(
                f"- **{cwe}** ({severity}) `{rule}` @ {host}: {message[:200]}"
            )
        output = "\n".join(det_block_lines) + "\n\n" + output

    console.print("\n[bold green]═══ Resumen de la investigación ═══[/bold green]\n")
    console.print(output)

    # F203.F — Write-through al learning loop (best-effort, no bloquea exit)
    if not args.no_writeback:
        try:
            from kryon.services.investigate_writeback import write_back_from_investigate
            exp_id = write_back_from_investigate(prompt, hints, result)
            if exp_id:
                console.print(f"\n[dim]💾 experience persisted: {exp_id}[/dim]")
        except Exception as e:  # noqa: BLE001
            console.print(f"\n[dim]write-back skipped: {e}[/dim]")

    # Persist transcript if --out given
    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = __import__("datetime").datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = out_dir / f"investigate-{ts}.md"
        out_path.write_text(
            f"# Investigate Transcript\n\n"
            f"**Prompt**: {prompt}\n\n"
            f"**Mode**: {hints.get('mode')}\n\n"
            f"**Active**: {active}\n\n"
            f"## Output\n\n{output}\n",
            encoding="utf-8",
        )
        console.print(f"\n[green]transcript →[/green] {out_path}")

    return 0


def add_investigate_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "investigate",
        help="F203.A — open-ended ReAct investigation (no fixed phases)",
        description=(
            "Open-ended investigative agent loop. "
            "Unlike `engage` (which has fixed phases 1-6), `investigate` lets "
            "the agent decide tools and iteration. Banca-safe by default "
            "(passive only); use --active to enable nmap/nuclei/etc."
        ),
    )
    p.add_argument(
        "query",
        nargs="?",
        default="",
        help="natural-language description of what to investigate "
        "(e.g. 'audita https://eaula.ing.una.py'). "
        "NOTE: usa positional, no le pongas --query.",
    )
    p.add_argument(
        "--url",
        default="",
        help="explicit URL to investigate (alternative/complement to prompt)",
    )
    p.add_argument(
        "--active",
        action="store_true",
        help="enable active probing tools (nmap/nuclei/sqlmap). Requires written "
        "authorization. KRYON_INVESTIGATE_ACTIVE=1 env var also enables.",
    )
    p.add_argument(
        "--max-turns",
        type=int,
        default=30,
        help="maximum agent turns before stopping (default: 30)",
    )
    p.add_argument(
        "--reflect-every",
        type=int,
        default=4,
        help="F203.C — inject reflection turn every N turns "
        "(default: 4, 0 = disabled). Forces autocrítica + stuck pattern detection.",
    )
    p.add_argument(
        "--no-writeback",
        action="store_true",
        help="F203.F — skip persisting the run to the learning loop. "
        "Default: write-back enabled (KRYON_NO_WRITEBACK=1 env also disables).",
    )
    p.add_argument(
        "--no-hybrid",
        action="store_true",
        help="F203.M — skip deterministic Phase 2 checks before agent loop. "
        "Default: hybrid mode ON (runs HTTP/MySQL detectors first, inyecta "
        "findings al prompt del agent).",
    )
    # F203.N.2 — creds-aware deep audit
    p.add_argument(
        "--ssh-user", default="",
        help="F203.N.2 — SSH user for deep audit (sshd_config / users / banner). "
        "Without it, only banner-grab finding emitted.",
    )
    p.add_argument(
        "--ssh-pass", default="",
        help="F203.N.2 — SSH password (alternativa: --ssh-key). Banca-safe: "
        "passwd se pasa como param, no se persiste a disco.",
    )
    p.add_argument(
        "--ssh-key", default="",
        help="F203.N.2 — ruta a SSH private key (preferido sobre --ssh-pass).",
    )
    p.add_argument(
        "--db-user", default="",
        help="F203.N.2 — MySQL user para F202.W deep audit (have_ssl / SHOW "
        "GRANTS / mysql.user audit).",
    )
    p.add_argument(
        "--db-pass", default="",
        help="F203.N.2 — MySQL password. Promovido a KRYON_DB_PASSWORD env solo "
        "durante la fase deterministica.",
    )
    # F203.N.3 — opt-in batteries con dependencia externa
    p.add_argument(
        "--include-dns-checks", action="store_true",
        help="F203.N.3 — ejecuta batería DNS (zone transfer, chaos leak, dnssec, "
        "open resolver, reverse enum) cuando port=53 o scheme=dns://. Requiere "
        "nslookup/dig en PATH (graceful skip si falta).",
    )
    p.add_argument(
        "--include-smb-checks", action="store_true",
        help="F203.N.3 — ejecuta SMB anonymous shares (port 445 / smb:// scheme). "
        "Requiere smbclient en PATH (graceful skip si falta).",
    )
    p.add_argument(
        "--out",
        default="",
        help="output directory for the transcript (default: don't persist)",
    )
    return p


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    add_investigate_subparser(sub)
    a = parser.parse_args()
    if a.command == "investigate":
        sys.exit(run_investigate(a))
    parser.print_help()
    sys.exit(2)
