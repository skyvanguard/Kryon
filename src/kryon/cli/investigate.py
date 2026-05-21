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
        f"Cuando termines, emití un **resumen ejecutivo** con: lo que aprendiste, "
        f"hallazgos preliminares (si aplican), y próximos pasos sugeridos para el operador.\n"
    )


def run_investigate(args: argparse.Namespace) -> int:
    """Main entry point for `kryon investigate`."""
    from rich.console import Console

    console = Console()

    prompt = args.prompt
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
    max_turns = args.max_turns

    console.print(f"[dim]starting ReAct loop (max_turns={max_turns})[/dim]\n")

    async def _run() -> Any:
        return await Runner.run(
            agent,
            input=full_prompt,
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
    console.print("\n[bold green]═══ Resumen de la investigación ═══[/bold green]\n")
    console.print(output)

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
        "prompt",
        nargs="?",
        default="",
        help="natural-language description of what to investigate "
        "(e.g. 'audita https://eaula.ing.una.py')",
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
