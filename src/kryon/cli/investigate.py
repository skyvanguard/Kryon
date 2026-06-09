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
        hints["keywords"].extend(
            [
                "webapp",
                "web vulnerability",
                "http",
                "cwe-79",
                "cwe-89",
                "cwe-352",
                "cwe-22",
                "cwe-918",
            ]
        )

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
        f"## Formato del reporte final (OBLIGATORIO — separar confirmado de recomendado)\n\n"
        f"Emití DOS secciones bien separadas. NO mezcles:\n\n"
        f"### ✅ Hallazgos confirmados\n"
        f"Solo vulnerabilidades que **observaste con evidencia** (findings deterministas "
        f"inyectados arriba + lo que vos verificaste con una tool). Acá SÍ usá la etiqueta "
        f"`CWE-XXX` por cada hallazgo, con la evidencia concreta. Si no lo confirmaste, NO va acá.\n\n"
        f"### 🔎 A verificar (NO confirmado)\n"
        f"Clases de vulnerabilidad que valdría la pena testear pero que **NO confirmaste**. "
        f"Acá describí en prosa el qué y el cómo (ej: 'probar inyección SQL en el parámetro q "
        f"con sqlmap'). **PROHIBIDO usar la etiqueta `CWE-XXX` en esta sección** — una "
        f"recomendación no es un hallazgo, y etiquetarla como CWE la haría pasar por confirmada. "
        f"Usá el nombre de la clase en texto (SQLi, XSS, CSRF…), nunca el código CWE.\n\n"
        f"Regla de oro: un `CWE-XXX` en el reporte = afirmás que ESE defecto existe y lo viste. "
        f"Si solo lo sospechás, va en 'A verificar' sin código CWE.\n"
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
            _check_security_headers,
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
            "https": 443,
            "http": 80,
            "ssh": 22,
            "mysql": 3306,
            "postgres": 5432,
            "postgresql": 5432,
            "redis": 6379,
            "mongodb": 27017,
            "dns": 53,
            "smb": 445,
            "cifs": 445,
        }
        port = defaults.get(scheme)
        if port is None:
            return []

    findings: list = []

    # HTTP / HTTPS
    if scheme in ("http", "https") or port in (80, 443, 8080, 8443, 8000, 8888):
        svc = DiscoveredService(
            host=host,
            port=port,
            state="open",
            service="https" if scheme == "https" or port == 443 else "http",
        )
        findings.extend(_safe_call(_check_http, svc))
        findings.extend(_safe_call(_check_http_cookie_flags, svc))
        # Missing security headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options)
        findings.extend(_safe_call(_check_security_headers, svc))
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
            findings.extend(_safe_call(_check_ssh, svc, ssh_target, ssh_password or None))
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


def _run_source_review_phase(code_path: str, *, max_files: int = 25) -> list:
    """Mythos-style source review over a local code tree.

    Runs the file-by-file reasoning review (intelligence.source_review)
    with the security model and returns engage.Finding objects so they
    inject into the agent prompt + output exactly like the URL-based
    deterministic phase. Skips silently on any error — the LLM agent
    still runs.
    """
    try:
        from kryon.intelligence.source_review import OllamaReviewer, review_tree
    except ImportError:
        return []

    root = Path(code_path).expanduser()
    if not root.exists():
        return []
    try:
        result = review_tree(root, reviewer=OllamaReviewer(), max_files=max_files)
    except Exception:  # noqa: BLE001 — defensive; LLM agent still runs
        return []
    return [f.to_engage_finding() for f in result.findings]


def _run_webexploit_phase(
    url: str,
    *,
    enable_nuclei: bool = False,
    max_depth: int = 2,
    max_urls: int = 40,
    web_auth: dict | None = None,
) -> list:
    """F57 deterministic web-pentest sweep → engage.Finding list (Phase 5).

    Runs the unified webexploit pipeline (crawl → planner_web → hunter_web →
    validator_web, offline / no LLM escalation) and converts non-FP
    BankingFindings into engage.Finding so they inject as ground truth
    like the other deterministic checks. This is the autonomous wiring of
    the previously-dormant F57 pipeline (it was only reachable via the
    ``/webpentest`` REPL command). ACTIVE — sends payloads; the caller
    gates it behind ``--active``. Skips silently on any error.
    """
    from urllib.parse import urlparse

    try:
        from kryon.cli.engage import Finding
        from kryon.webexploit.crawler import CrawlConfig, Crawler
        from kryon.webexploit.orchestrator import run_engagement
        from kryon.webexploit.proxy import HttpSession
    except ImportError:
        return []

    host = urlparse(url).hostname or ""
    if not host:
        return []

    try:
        session = HttpSession(base_url=url, verify_tls=False)
        graph = Crawler(session, config=CrawlConfig(max_depth=max_depth, max_urls=max_urls)).crawl([url])

        def _factory() -> HttpSession:
            return HttpSession(base_url=url, verify_tls=False)

        report = run_engagement(session, _factory, graph, base_url=url, enable_nuclei=enable_nuclei, web_auth=web_auth)
    except Exception:  # noqa: BLE001 — LLM agent still runs
        return []

    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings: list = []
    for vf in report.findings:
        if vf.status == "FALSE_POSITIVE":
            continue
        bf = vf.finding
        findings.append(
            Finding(
                cwe=bf.cwe_id or "?",
                severity=bf.severity,
                host=host,
                rule_id=bf.probe_id,
                message=bf.title,
                evidence=bf.evidence[:1024],
                remediation=bf.remediation,
                severity_rank=rank.get(bf.severity, 99),
                needs_verification=(vf.status != "CONFIRMED"),
            )
        )
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
        prompt = f"{prompt} (URL declarada explícitamente: {args.url})" if prompt else f"Investigá {args.url}"
    if not prompt:
        console.print("[red]error: provide a prompt or --url[/red]")
        return 2

    hints = _classify_intent(prompt)
    active = args.active or os.environ.get("KRYON_INVESTIGATE_ACTIVE", "").lower() in ("1", "true", "yes")

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
        console.print(f"[dim]skills loaded: {[s.name for s in matched[:6]]} (total={len(matched)})[/dim]")

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
    if not args.no_hybrid and hints.get("mode") == "code_sast" and hints.get("code_path"):
        # Mythos-style source review for local code trees.
        console.print(
            f"[cyan]🔬 source-review phase:[/cyan] {hints['code_path']} "
            f"(max {args.sast_max_files} files, model "
            f"{os.environ.get('KRYON_SOURCE_REVIEW_MODEL', 'kryon-foundation-sec')})"
        )
        sr = _run_source_review_phase(hints["code_path"], max_files=args.sast_max_files)
        if sr:
            deterministic_findings.extend(sr)
    if not args.no_hybrid and hints.get("mode") != "code_sast":
        urls_to_check = list(hints.get("urls") or [])
        if args.url and args.url not in urls_to_check:
            urls_to_check.append(args.url)
        # Backstop wall-bound per URL. The detectors carry their own per-probe
        # timeouts, but this guarantees one misbehaving detector can't block the
        # whole run (which is sync here, before the async agent loop).
        import concurrent.futures

        _det_timeout = float(os.environ.get("KRYON_DETERMINISTIC_TIMEOUT_S", "120"))
        for u in urls_to_check:
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _ex:
                    _fut = _ex.submit(
                        _run_deterministic_phase,
                        u,
                        ssh_user=args.ssh_user,
                        ssh_password=args.ssh_pass,
                        ssh_key=args.ssh_key,
                        db_user=args.db_user,
                        db_password=args.db_pass,
                        include_dns=args.include_dns_checks,
                        include_smb=args.include_smb_checks,
                    )
                    df = _fut.result(timeout=_det_timeout)
            except concurrent.futures.TimeoutError:
                console.print(f"[yellow]⚠ fase determinista excedió {_det_timeout:.0f}s para {u} — saltando[/yellow]")
                df = None
            except Exception as e:  # noqa: BLE001 — detectors must never break the run
                console.print(f"[yellow]deterministic phase warning ({u}): {e}[/yellow]")
                df = None
            if df:
                deterministic_findings.extend(df)

        # F57 webexploit sweep — ACTIVE only (sends payloads). Adds the unified
        # deterministic web-vuln coverage (SQLi/XSS/LFI/SSTI/cmd-inj/XXE/IDOR/
        # SSRF/CORS/JWT/git-leak) + opt-in nuclei known-CVE library. This is the
        # autonomous wiring of the F57 pipeline (was /webpentest-only).
        if active:
            enable_nuclei = os.environ.get("KRYON_RED_TEAM", "").strip().lower() in ("1", "true", "yes")
            # Comprehensive sweep (surface discovery + injection over dozens of
            # endpoints + headless cookie check + authenticated IDOR/mass-assign)
            # is heavy on rich targets; 600s default so its findings aren't
            # dropped. Override with KRYON_WEBEXPLOIT_TIMEOUT_S.
            _wx_timeout = float(os.environ.get("KRYON_WEBEXPLOIT_TIMEOUT_S", "600"))
            # Authenticated probing mode — operator-supplied web creds unlock
            # IDOR / mass-assignment probes (unreachable unauthenticated).
            _web_auth = None
            if getattr(args, "web_login_url", "") and getattr(args, "web_user", ""):
                login_url = args.web_login_url
                if not login_url.lower().startswith(("http://", "https://")) and args.url:
                    login_url = args.url.rstrip("/") + "/" + login_url.lstrip("/")
                _web_auth = {
                    "login_url": login_url,
                    "username": args.web_user,
                    "password": args.web_pass,
                    "token_json_path": args.web_token_path,
                }
            for u in urls_to_check:
                if not u.lower().startswith(("http://", "https://")):
                    continue
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _ex:
                        _fut = _ex.submit(_run_webexploit_phase, u, enable_nuclei=enable_nuclei, web_auth=_web_auth)
                        wf = _fut.result(timeout=_wx_timeout)
                except concurrent.futures.TimeoutError:
                    console.print(f"[yellow]⚠ webexploit sweep excedió {_wx_timeout:.0f}s para {u} — saltando[/yellow]")
                    wf = None
                except Exception as e:  # noqa: BLE001 — must never break the run
                    console.print(f"[yellow]webexploit sweep warning ({u}): {e}[/yellow]")
                    wf = None
                if wf:
                    console.print(f"[cyan]🕸 webexploit sweep:[/cyan] {len(wf)} findings en {u}")
                    deterministic_findings.extend(wf)

        if deterministic_findings:
            console.print(
                f"[cyan]🔬 deterministic phase:[/cyan] "
                f"{len(deterministic_findings)} finding(s) detected before agent loop"
            )
            for f in deterministic_findings[:8]:
                console.print(f"  [dim]→ {getattr(f, 'cwe', '?')} {getattr(f, 'rule_id', '?')}[/dim]")
            full_prompt = full_prompt + _format_findings_for_prompt(deterministic_findings)

    max_turns = args.max_turns
    reflect_every = args.reflect_every

    if reflect_every > 0:
        console.print(
            f"[dim]starting ReAct loop with reflection every {reflect_every} turns (max_turns={max_turns})[/dim]\n"
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

            # Outer wall-bound on ALL pre_hooks. Each hook already has its own
            # timeout + orphan-kill, but a skill with many hooks (or a slow
            # nuclei/sqlmap target) could still stall the run before the agent
            # loop starts. Cap the whole phase so the run always progresses.
            _ph_timeout = float(os.environ.get("KRYON_PREHOOK_TOTAL_TIMEOUT_S", "180"))
            pre_hook_suffix = await asyncio.wait_for(
                maybe_run_pre_hooks(agent, full_prompt, console),
                timeout=_ph_timeout,
            )
            if pre_hook_suffix:
                agent_input = full_prompt + pre_hook_suffix
        except asyncio.TimeoutError:
            console.print(f"[yellow]⚠ pre_hooks excedieron {_ph_timeout:.0f}s — continuando sin su salida[/yellow]")
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

    agent_error: str | None = None
    try:
        result = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted by user[/yellow]")
        return 130
    except Exception as e:  # noqa: BLE001
        # Don't abort empty-handed. The deterministic detectors may have
        # already produced findings, and a stuck/looping (or otherwise
        # crashed) agent run still has value as a PARTIAL report. Fall
        # through to build + persist a report instead of returning with no
        # artifact — converts a "failed, no report" run into a "partial
        # findings" run. The reflective runner finalizes StuckError
        # gracefully (so it rarely reaches here), but the non-reflective
        # Runner.run path and any unexpected crash land here as a net.
        from kryon.sdk.agents.run_outcome import classify_run_exception

        ename = type(e).__name__
        console.print(f"[yellow]agent run ended early ({ename}: {e}) — emitting partial report[/yellow]")
        result = None
        # Use the shared classifier so the partial-report wording for
        # stuck / max-turns / budget matches the reflective runner + REST route.
        _outcome = classify_run_exception(e)
        agent_error = _outcome.message if _outcome is not None else f"{ename}: {e}"

    output = getattr(result, "final_output", None) or ""
    if agent_error and not output:
        output = (
            f"⚠️ El run del agente terminó temprano ({agent_error}). "
            f"Los hallazgos deterministas abajo son válidos; el análisis del "
            f"agente quedó incompleto y debe re-ejecutarse o continuarse."
        )

    # Observability + anti-bluff — build a structured report that separates
    # VERIFIED (deterministic detectors + validate_* confirmations) from
    # ALLEGED (the LLM's prose). Persist it to a stable path and print it
    # FLUSHED so it's visible even when piped (non-TTY) — the old single
    # ``console.print`` was lost in pipes and left runs with no artifact.
    try:
        from kryon.services.investigate_writeback import chain_from_result

        # F203.K — extract from new_items with RunHooks-captured fallback, so
        # the report never claims "Tool calls: 0" while the agent ran recon
        # (chunks dropped by MaxTurns, or a stuck/crashed run).
        chain = chain_from_result(result)
    except Exception:  # noqa: BLE001
        chain = []
    from kryon.cli.investigate_report import (
        build_investigate_report,
        persist_investigate_report,
    )

    report = build_investigate_report(
        prompt=prompt,
        active=active,
        output=output,
        deterministic_findings=deterministic_findings,
        chain=chain,
    )
    console.print("\n[bold green]═══ Resumen de la investigación ═══[/bold green]\n")
    print(report, flush=True)
    try:
        report_path = persist_investigate_report(report)
        console.print(f"\n[dim]📄 reporte → {report_path}[/dim]")
    except Exception as e:  # noqa: BLE001
        console.print(f"\n[dim]reporte no persistido: {e}[/dim]")

    # F203.F — Write-through al learning loop (best-effort, no bloquea exit).
    # Skip when the run crashed (result is None): nothing coherent to learn from.
    if not args.no_writeback and result is not None:
        try:
            from kryon.services.investigate_writeback import write_back_from_investigate

            exp_id = write_back_from_investigate(prompt, hints, result)
            if exp_id:
                console.print(f"\n[dim]💾 experience persisted: {exp_id}[/dim]")
        except Exception as e:  # noqa: BLE001
            console.print(f"\n[dim]write-back skipped: {e}[/dim]")

    # Also persist the same structured report to --out dir if given.
    if args.out:
        import datetime as _dt

        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = out_dir / f"investigate-{ts}.md"
        out_path.write_text(report, encoding="utf-8")
        console.print(f"\n[green]reporte →[/green] {out_path}")

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
    # F1.5 — respetar KRYON_MAX_TURNS como default del flag (el flag explícito
    # sigue ganando). Antes investigate ignoraba la env var → corría 30 turnos
    # siempre, peligroso para el gasto en el perfil API.
    _mt_env = os.environ.get("KRYON_MAX_TURNS", "").strip()
    _default_max_turns = int(_mt_env) if _mt_env.isdigit() else 30
    p.add_argument(
        "--max-turns",
        type=int,
        default=_default_max_turns,
        help="maximum agent turns before stopping (default: 30, or $KRYON_MAX_TURNS)",
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
        "findings al prompt del agent). For code paths, also skips the "
        "Mythos-style source-review phase.",
    )
    p.add_argument(
        "--sast-max-files",
        type=int,
        default=25,
        help="source-review: max files sent to the model per run (triage "
        "ranks by sink-density; default 25). Only applies to local code paths.",
    )
    # F203.N.2 — creds-aware deep audit
    p.add_argument(
        "--ssh-user",
        default="",
        help="F203.N.2 — SSH user for deep audit (sshd_config / users / banner). "
        "Without it, only banner-grab finding emitted.",
    )
    p.add_argument(
        "--ssh-pass",
        default="",
        help="F203.N.2 — SSH password (alternativa: --ssh-key). Banca-safe: "
        "passwd se pasa como param, no se persiste a disco.",
    )
    p.add_argument(
        "--ssh-key",
        default="",
        help="F203.N.2 — ruta a SSH private key (preferido sobre --ssh-pass).",
    )
    p.add_argument(
        "--db-user",
        default="",
        help="F203.N.2 — MySQL user para F202.W deep audit (have_ssl / SHOW GRANTS / mysql.user audit).",
    )
    p.add_argument(
        "--db-pass",
        default="",
        help="F203.N.2 — MySQL password. Promovido a KRYON_DB_PASSWORD env solo durante la fase deterministica.",
    )
    # F203.N.3 — opt-in batteries con dependencia externa
    p.add_argument(
        "--include-dns-checks",
        action="store_true",
        help="F203.N.3 — ejecuta batería DNS (zone transfer, chaos leak, dnssec, "
        "open resolver, reverse enum) cuando port=53 o scheme=dns://. Requiere "
        "nslookup/dig en PATH (graceful skip si falta).",
    )
    p.add_argument(
        "--include-smb-checks",
        action="store_true",
        help="F203.N.3 — ejecuta SMB anonymous shares (port 445 / smb:// scheme). "
        "Requiere smbclient en PATH (graceful skip si falta).",
    )
    p.add_argument(
        "--web-login-url",
        default="",
        help="Authenticated probing: login endpoint (absolute or relative to --url). "
        "POSTs {email,password} as JSON; unlocks IDOR (CWE-639) + mass-assignment "
        "(CWE-915) probes. Requires --active and an authorized engagement.",
    )
    p.add_argument("--web-user", default="", help="Username/email for --web-login-url.")
    p.add_argument("--web-pass", default="", help="Password for --web-login-url.")
    p.add_argument(
        "--web-token-path",
        default="authentication.token",
        help="Dotted JSON path to the bearer token in the login response "
        "(default: authentication.token, matches OWASP Juice Shop).",
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
