"""Shared target-orchestration — makes the REPL engage-grade.

The three entry points historically diverged: ``engage`` did the rich pipeline
(nmap discovery → per-service battery → device-family compliance → skill
hot-swap), while the interactive REPL only ran the read-only battery against the
*single* resolved URL — no discovery, no framework auto-select, no profile-driven
skills. So typing ``auditá 10.0.0.5`` in the REPL got a far thinner deterministic
pass than ``kryon engage 10.0.0.5``.

This module composes the SAME reusable building blocks the other entry points
already expose into one deterministic orchestrator the REPL calls when it
resolves a target:

    discover (nmap) → detect device families → battery over EVERY open service
    → per-family compliance → profile-driven skill hot-swap → dedup → ground truth

The routing is 100% deterministic — the small local model never decides *which*
layer runs; it narrates the ground truth and chases the residue. Everything is
best-effort and wrapped so it can never crash the REPL turn; on any failure the
caller falls back to whatever it had.

``run_target_orchestration`` is a thin composer over one ``_stage_*`` helper per
pipeline step. Each helper takes its engage/investigate dependency INJECTED, so
it's unit-testable with a fake and never has to import the heavy CLI modules.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kryon.util.net import bare_host as _bare_host, is_cidr as _is_cidr, scheme_for_service

logger = logging.getLogger(__name__)

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


@dataclass
class OrchestrationResult:
    findings: list = field(default_factory=list)
    ground_truth: str = ""
    services: list = field(default_factory=list)  # DiscoveredService
    families: list[str] = field(default_factory=list)
    selected_skills: list[str] = field(default_factory=list)
    discovery_ran: bool = False
    note: str = ""  # e.g. CIDR rejection message


def _service_url(host: str, svc: Any) -> str:
    """Discovered service → a URL the battery understands (branches on scheme/port)."""
    port = getattr(svc, "port", 0) or 0
    return f"{scheme_for_service(port, getattr(svc, 'service', '') or '')}://{host}:{port}"


def _profile_intent(families: list[str], findings: list) -> tuple[dict, str]:
    """Build the (profile, intent) for loader.match — same shape engage uses to
    hot-swap skills against the detected target (device families + finding CWEs)."""
    profile = {"tech": list(families or [])}
    extra: list[str] = []
    for f in findings or []:
        rid = (getattr(f, "rule_id", "") or "").lower()
        cwe = (getattr(f, "cwe", "") or "").lower()
        if rid.startswith("http-") or "http" in rid:
            extra += ["webapp", "http", "web vulnerability", "cwe-79", "cwe-89", "cwe-22"]
        if "cookie" in rid or "samesite" in rid or "csrf" in cwe:
            extra += ["cookie", "csrf", "samesite", "cwe-352"]
        if "ssh" in rid or "auth" in rid or "password" in rid or "credential" in rid:
            extra += ["auth", "authentication", "ssh", "cwe-287"]
        if "mysql" in rid or "postgres" in rid or "mongo" in rid or "redis" in rid:
            extra += ["sqli", "sql injection", "database", "cwe-89"]
        if cwe.startswith("cwe-"):
            extra.append(cwe)
    # T3-A9: the matcher is stateless (no recon-vs-post-foothold stage), and the intent
    # built from posture findings never contained privesc keywords — so linux-privesc/
    # active-directory-recon NEVER loaded, breaking the core THM foothold→privesc loop.
    # For a capable model make the privesc/post-exploitation playbook available from the
    # start (it drives the whole chain); the 4B-local stays posture-scoped (banca-safe).
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    if is_capable_model():
        extra += [
            "privesc",
            "privilege escalation",
            "linpeas",
            "suid",
            "sudo",
            "post-exploitation",
            "gtfobins",
            "kerberoast",
            "dcsync",
        ]
    seen: set[str] = set()
    uniq = [k for k in extra if not (k in seen or seen.add(k))]
    intent = " ".join(list(families or []) + uniq + ["audit"]).strip()
    return profile, intent


# ---------------------------------------------------------------------------
# Pipeline stages — one helper per step, dependency-injected for testability.
# ---------------------------------------------------------------------------


def _stage_discover(
    target: str,
    host: str,
    *,
    discover: bool,
    console: Any,
    run_nmap: Callable[[str], Any],
    parse_nmap_xml: Callable[[Any, str], list],
) -> tuple[list, bool]:
    """Step 1 — nmap discovery. Returns (services, discovery_ran). Falls back to a
    single synthetic service for the raw target so coverage never regresses to zero."""
    services: list = []
    discovery_ran = False
    if discover:
        try:
            services = parse_nmap_xml(run_nmap(host), host)
            discovery_ran = True
        except Exception as exc:  # noqa: BLE001 — discovery best-effort
            _print(console, f"  [dim]discovery skipped: {exc}[/dim]")
    if not services:
        services = [_synthetic_service(target, host)]
    return services, discovery_ran


def _stage_families(services: list, *, detect_device_families: Callable[[list], list]) -> list[str]:
    """Step 2 — device-family detection (Proxmox / FortiGate / Windows-AD / …)."""
    try:
        return detect_device_families(services) or []
    except Exception as exc:  # noqa: BLE001
        logger.warning("device-family detection failed: %s", exc)
        return []


def _stage_battery(
    host: str,
    services: list,
    *,
    max_services: int,
    console: Any,
    run_deterministic_phase: Callable[..., list],
    ssh_user: str,
    ssh_password: str,
    ssh_key: str,
    db_user: str,
    db_password: str,
    include_dns: bool,
    include_smb: bool,
    run_web_enum_phase: Callable[..., list] | None = None,
) -> list:
    """Step 3 — read-only deterministic battery over every open service (deduped by port).

    T3-A5: also runs web-enum (ffuf dir/vhost discovery) on HTTP services when
    ``run_web_enum_phase`` is injected — the orchestrator (default-on, "engage-grade")
    used to run only the posture battery, giving the model headers/cookies but no
    discovered directories (the foothold surface)."""
    findings: list = []
    # T4-A4: curated banner→CVE over EVERY service (vsftpd/ProFTPd/Samba/Jenkins/…),
    # not just SSH — the one-shot known-CVE findings were dead for their own services.
    try:
        from kryon.cli.version_cve import correlate_services  # noqa: PLC0415

        findings.extend(correlate_services(services))
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.debug("banner→CVE correlation skipped: %s", exc)
    seen_ports: set[int] = set()
    for svc in services[:max_services]:
        port = getattr(svc, "port", 0) or 0
        if port in seen_ports:
            continue
        seen_ports.add(port)
        url = _service_url(host, svc)
        try:
            got = run_deterministic_phase(
                url,
                ssh_user=ssh_user,
                ssh_password=ssh_password,
                ssh_key=ssh_key,
                db_user=db_user,
                db_password=db_password,
                include_dns=include_dns,
                include_smb=include_smb,
            )
            findings.extend(got or [])
        except Exception as exc:  # noqa: BLE001 — one service failing ≠ abort
            _print(console, f"  [dim]battery {url} skipped: {exc}[/dim]")
        # T3-A5: ffuf dir/vhost discovery for HTTP services (foothold surface).
        if run_web_enum_phase is not None and url.startswith(("http://", "https://")):
            try:
                wf = run_web_enum_phase(url)
                findings.extend(wf or [])
            except Exception as exc:  # noqa: BLE001 — enumeration best-effort
                _print(console, f"  [dim]web-enum {url} skipped: {exc}[/dim]")
    return findings


def _stage_family_compliance(
    families: list[str],
    host: str,
    *,
    host_reachable: bool,
    ssh_user: str,
    ssh_key: str,
    console: Any,
    run_device_compliance: Callable[..., list],
    known_families: set[str],
) -> list:
    """Step 4 — per-family deterministic compliance (device checks). Needs host
    access (SSH); skipped for a remote target with no creds so a web audit doesn't
    hang on host-config checks the read-only battery already covered at net level."""
    findings: list = []
    ssh_target = f"{ssh_user}@{host}" if ssh_user else None
    for fam in families:
        if fam not in known_families or not host_reachable:
            continue
        try:
            findings.extend(
                run_device_compliance(console, family=fam, host=host, ssh_target=ssh_target, ssh_key=ssh_key or None)
                or []
            )
        except Exception as exc:  # noqa: BLE001
            _print(console, f"  [dim]{fam} compliance skipped: {exc}[/dim]")
    return findings


def _stage_hot_swap(
    agent: Any,
    *,
    families: list[str],
    findings: list,
    host_reachable: bool,
    console: Any,
) -> list[str]:
    """Step 5 — profile-driven skill hot-swap so the agent narrates with the right
    skills + fires their pre_hooks, exactly like engage's mid-engagement swap.
    Returns the selected skill names (empty when nothing swapped)."""
    if agent is None or not (families or findings):
        return []
    try:
        from kryon.skills.loader import SkillLoader
        from kryon.skills.unified_agent import update_agent_skills

        loader = getattr(agent, "_skill_loader", None) or SkillLoader()
        profile, intent = _profile_intent(families, findings)
        new_skills = loader.match(profile=profile, user_msg=intent)
        # Guard (same intent as the compliance skip): a host-compliance skill
        # declares a REQUIRED `run_compliance_audit` pre_hook that needs SSH creds.
        # Hot-swapping it against a remote target with no creds fires that pre_hook,
        # which hangs ~180s on the unreachable host and (being required) kills the
        # whole run — exactly what bit `audita <web>` in testing. Drop those skills
        # when the host isn't reachable; the read-only battery covered the net slice.
        if new_skills and not host_reachable:
            pruned = [s for s in new_skills if "run_compliance_audit" not in (getattr(s, "required_tools", None) or [])]
            if len(pruned) < len(new_skills):
                _print(
                    console,
                    f"  [dim]skipped {len(new_skills) - len(pruned)} host-compliance skill(s): "
                    "no SSH creds for this target[/dim]",
                )
            new_skills = pruned
        if new_skills:
            update_agent_skills(agent, new_skills)
            return [getattr(s, "name", str(s)) for s in new_skills]
    except Exception as exc:  # noqa: BLE001
        _print(console, f"  [dim]skill hot-swap skipped: {exc}[/dim]")
    return []


def _stage_dedup(findings: list) -> list:
    """Step 6 — cross-engine dedup (moat), default-on via KRYON_FINDING_DEDUP."""
    if os.environ.get("KRYON_FINDING_DEDUP", "true").strip().lower() in ("0", "false", "no", "off"):
        return findings
    try:
        from kryon.services.finding_dedup import dedupe_findings

        return dedupe_findings(findings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("finding dedup failed, using un-deduped findings: %s", exc)
        return findings


def _run_coro_sync(coro):
    """Run an async coroutine from this sync stage, whether or not a loop runs.

    ``run_target_orchestration`` is sync but may be invoked from inside the
    REPL's async turn; ``asyncio.run`` would then raise. Fall back to a fresh
    thread with its own loop. Best-effort — enrichment must never break the turn.
    """
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(coro)).result()


def _stage_ground_truth(findings: list, target: str) -> str:
    """Step 7 — format the confirmed findings as the ground-truth block for the LLM.

    When the one-day exploitation-context gate is on (``KRYON_CVE_EXPLOIT_CONTEXT``
    / red-team / capable), append the NVD description + PoC refs for any
    ``inferred`` version→CVE finding — the "87% recipe" that turns *"a CVE
    applies"* into the *what/where* the model needs to attempt confirmation.
    """
    if not findings:
        return ""
    try:
        from kryon.repl.engine_phase import format_engine_ground_truth

        block = format_engine_ground_truth(findings, target)
    except Exception as exc:  # noqa: BLE001
        logger.warning("ground-truth formatting failed: %s", exc)
        return ""

    try:
        from kryon.intelligence.cve_context_injector import (
            build_cve_exploitation_context,
            is_cve_exploit_context_enabled,
        )

        if is_cve_exploit_context_enabled():
            cve_ctx = _run_coro_sync(build_cve_exploitation_context(findings))
            if cve_ctx:
                block += cve_ctx
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
        logger.debug("CVE exploitation context skipped: %s", exc)

    return block


def run_target_orchestration(
    target: str,
    *,
    console: Any,
    agent: Any = None,
    include_dns: bool = False,
    include_smb: bool = False,
    ssh_user: str = "",
    ssh_password: str = "",
    ssh_key: str = "",
    db_user: str = "",
    db_password: str = "",
    discover: bool = True,
    max_services: int = 24,
) -> OrchestrationResult:
    """Deterministic engage-grade pipeline for one resolved target.

    Sync (like the REPL's ``run_engine_phase``). Never raises — every stage is
    guarded; partial results are returned so the caller can still narrate them.
    Thin composer: each numbered step is a ``_stage_*`` helper below.
    """
    result = OrchestrationResult()
    host = _bare_host(target)

    if _is_cidr(target):
        result.note = (
            f"'{target}' es un segmento (CIDR). El barrido por-host va por "
            "`kryon discover --queue-add` → `kryon queue process`, no por un solo turno."
        )
        return result
    if not host:
        return result

    # Lazy imports — keep this module import-light and avoid the engage<->repl cycle.
    try:
        from kryon.cli.engage import _detect_device_families, _parse_nmap_xml, _run_device_compliance, _run_nmap
        from kryon.cli.investigate import _run_deterministic_phase
    except Exception as exc:  # pragma: no cover
        result.note = f"orchestrator deps missing: {exc}"
        return result

    # 1 — Discovery (nmap).
    result.services, result.discovery_ran = _stage_discover(
        target,
        host,
        discover=discover,
        console=console,
        run_nmap=_run_nmap,
        parse_nmap_xml=_parse_nmap_xml,
    )

    # 2 — Device families.
    result.families = _stage_families(result.services, detect_device_families=_detect_device_families)

    # 3 — Battery over every open service.
    # T3-A5: wire ffuf dir/vhost discovery into the battery for HTTP services. It's
    # active recon, so only under red-team (the active/THM profile); the banca-safe
    # default stays posture-only. Import inline to avoid an investigate↔orchestrator cycle.
    _web_enum = None
    try:
        from kryon.util.env import is_red_team  # noqa: PLC0415

        if is_red_team():
            from kryon.cli.investigate import _run_web_enum_phase  # noqa: PLC0415

            _web_enum = _run_web_enum_phase
    except Exception:  # noqa: BLE001 — wiring is best-effort
        _web_enum = None
    findings = _stage_battery(
        host,
        result.services,
        max_services=max_services,
        console=console,
        run_deterministic_phase=_run_deterministic_phase,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key=ssh_key,
        db_user=db_user,
        db_password=db_password,
        include_dns=include_dns,
        include_smb=include_smb,
        run_web_enum_phase=_web_enum,
    )

    # 4 — Per-family compliance (host access required).
    host_reachable = bool(ssh_user or ssh_key) or host in _LOCAL_HOSTS
    findings += _stage_family_compliance(
        result.families,
        host,
        host_reachable=host_reachable,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        console=console,
        run_device_compliance=_run_device_compliance,
        known_families=_device_family_keys(),
    )

    # 5 — Profile-driven skill hot-swap.
    result.selected_skills = _stage_hot_swap(
        agent,
        families=result.families,
        findings=findings,
        host_reachable=host_reachable,
        console=console,
    )

    # 6 — Dedup (cross-engine moat).
    findings = _stage_dedup(findings)
    result.findings = findings

    # 7 — Ground-truth block for the LLM.
    result.ground_truth = _stage_ground_truth(findings, target)

    return result


def _synthetic_service(target: str, host: str) -> Any:
    """A DiscoveredService for the raw target when discovery yields nothing."""
    from kryon.cli.engage import DiscoveredService

    port = 0
    if "://" in target:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        tail = target.split("/", 1)[0]
        if ":" in tail:
            try:
                port = int(tail.rsplit(":", 1)[1])
            except ValueError:
                port = 0
    return DiscoveredService(host=host, port=port or 443, state="open", service="")


def _device_family_keys() -> set[str]:
    try:
        from kryon.cli.engage import _DEVICE_FAMILIES

        return {row[0] for row in _DEVICE_FAMILIES}
    except Exception as exc:  # noqa: BLE001
        logger.debug("device-family keys unavailable: %s", exc)
        return set()


def _print(console: Any, msg: str) -> None:
    # Always leave a log trace, even when console is a closed/non-interactive
    # stream (headless `queue process` batches) — otherwise the "reported"
    # errors above vanish with no record anywhere.
    logger.debug("orchestrator: %s", msg)
    try:
        console.print(msg)
    except Exception as exc:  # noqa: BLE001
        logger.debug("console.print failed: %s", exc)
