"""REPL deterministic engine phase + operator-terminal narration.

Wires the **read-only** deterministic detector battery (the same
``_run_deterministic_phase`` that ``kryon engage`` / ``kryon investigate``
use) into the interactive REPL, so a plain request like ``analizá 10.0.0.5``
fires the engine BEFORE the LLM and injects ground-truth findings — instead
of the model improvising the whole analysis by itself.

Design contract:

* **Read-only only.** This module runs the passive detector battery
  (HTTP headers / cookies / CSRF / TLS / banners / SSH / MySQL / DNS / SMB).
  Payload-sending sweeps (nuclei/sqlmap) stay behind the existing
  ``KRYON_RED_TEAM`` / active gates — they are NOT auto-fired from here.
* **Target resolution is explicit.** A turn only triggers the engine when a
  target can be resolved from (a) the message text, (b) a session target set
  by the operator, or (c) ``KRYON_TARGET_HOST``. No target → no auto-scan.
* **Narration is faithful.** The operator-terminal narration only reports
  detectors that actually produced findings; a clean run says so honestly.

Public surface:
  - ``resolve_target(user_input, session_target) -> str | None``
  - ``is_analysis_request(user_input) -> bool``
  - ``normalize_to_url(target) -> str``
  - ``build_narration_lines(host, findings, duration_s) -> list[str]``
  - ``format_engine_ground_truth(findings, target) -> str``
  - ``run_engine_phase(target, *, console, ...) -> EngineResult``
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

# Matches an IPv4 literal (octet-validated), a dotted hostname (with a TLD), or
# ``localhost``, each with an optional scheme, port and path. Also matches a
# CIDR block so the caller can detect + reject it cleanly. Deliberately
# conservative so a stray word with a dot does not read as a target.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"  # 0-255
_TARGET_RE = re.compile(
    r"(?P<target>"
    r"(?:[a-z]+://)?"  # optional scheme (http/https/ssh/mysql/…)
    r"(?:"
    rf"(?:{_OCTET}\.){{3}}{_OCTET}(?!\d)(?:/\d{{1,2}})?"  # IPv4 (+ optional /CIDR)
    r"|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"  # dotted hostname
    r"|localhost"
    r")"
    r"(?::\d{1,5})?"  # optional port
    r"(?:/[^\s]*)?"  # optional path
    r")"
)

# Known non-web service ports → scheme (canonical map, was a thin local copy).
from kryon.util.net import PORT_TO_SCHEME as _PORT_SCHEME  # noqa: E402

# Intent stems (substring match, accent-tolerant on the common ones). A turn
# is treated as an analysis request when any stem appears. Kept broad on
# purpose: the target gate below is what actually prevents unwanted scans.
_ANALYSIS_STEMS: tuple[str, ...] = (
    "analiz",
    "análisis",
    "analisis",
    "audit",
    "auditor",
    "escane",
    "scan",
    "seguridad",
    "security",
    "vulnerab",
    "pentest",
    "revis",
    "recon",
    "hacke",
    "hacking",
    "exploit",
    "evalua",
    "evalúa",
    # Broadened after the gap audit — plausible analysis phrasings that used to
    # silently skip the engine and go straight to the LLM.
    "investig",
    "check",
    "chequea",
    "test",
    "enumer",
    "cve",
    "debilidad",
    "weakness",
    "identific",
    "reconoc",
)


# A bare ``name.ext`` where ext is a code/asset file type — reads as a filename,
# NOT a network host (so "analizá el package.json" doesn't scan http://package.json).
_FILENAME_RE = re.compile(
    r"^[a-z0-9_.-]+\.(?:json|jsonl|js|mjs|cjs|ts|tsx|jsx|py|pyc|ipynb|md|rst|txt|"
    r"ya?ml|toml|lock|cfg|conf|ini|xml|html?|css|scss|sh|bash|zsh|go|rs|rb|php|"
    r"java|c|cpp|cc|h|hpp|cs|kt|swift|sql|csv|tsv|log|bak|tmp|env|proto|pdf|docx?|"
    r"xlsx?|png|jpe?g|gif|svg|webp|ico|zip|tar|gz|tgz|rar|7z|exe|dll|so|dylib|"
    r"bin|pem|key|crt|cert|pub|p12|pfx)$",
    re.IGNORECASE,
)


# Second-level-domain markers (e.g. .com.py, .gov.py, .co.uk). A token carrying
# one is a DOMAIN, not a file — even when its ccTLD collides with a code/asset
# extension: .py=Paraguay, .sh=Solomon Is., .rs=Serbia, .rb?, .pl=Poland… Without
# this every Paraguayan `*.com.py` host was mis-read as a Python file, so
# resolve_target returned None and the whole deterministic phase silently skipped
# it (observed live: `audita example.com` never ran discovery/battery).
_DOMAIN_SLD_RE = re.compile(
    r"\.(?:com|net|org|edu|gov|gob|mil|co|ac|or|ne|nom|web)\.[a-z]{2,3}$",
    re.IGNORECASE,
)


def _looks_like_filename(candidate: str) -> bool:
    """True when a target token is really a filename (no scheme/port/path)."""
    if _DOMAIN_SLD_RE.search(candidate):
        return False  # a domain (e.g. example.com), not a file
    return (
        "://" not in candidate and ":" not in candidate and "/" not in candidate and bool(_FILENAME_RE.match(candidate))
    )


def resolve_target(user_input: str, session_target: str | None = None) -> str | None:
    """Resolve the target for this turn.

    Priority: an address in the message text → the session target the operator
    set → the ``KRYON_TARGET_HOST`` env var. Returns ``None`` when nothing is
    resolvable (the caller then leaves the turn to the LLM as before).
    """
    if user_input:
        match = _TARGET_RE.search(user_input)
        if match and not _looks_like_filename(match.group("target")):
            return match.group("target")
    if session_target:
        return session_target.strip() or None
    env_target = os.environ.get("KRYON_TARGET_HOST", "").strip()
    return env_target or None


def is_analysis_request(user_input: str) -> bool:
    """Heuristic: does this turn look like a security-analysis request?"""
    if not user_input:
        return False
    low = user_input.lower()
    return any(stem in low for stem in _ANALYSIS_STEMS)


def normalize_to_url(target: str) -> str:
    """Normalize a bare host/IP to an http URL the detector phase understands.

    ``_run_deterministic_phase`` keys off ``urlparse(url).hostname``; a bare
    ``10.0.0.5`` yields an empty hostname, so we prepend a scheme when missing.
    Existing ``http(s)://`` targets pass through untouched.
    """
    t = (target or "").strip()
    if not t:
        return ""
    if t.startswith(("http://", "https://")):
        return t
    return "http://" + t


def candidate_urls(target: str) -> list[str]:
    """URLs to probe for a target, most-likely-correct first.

    - An explicit scheme (``http/https/ssh/mysql/…``) is honoured as-is.
    - A bare host with a known **non-web service port** (``:22``, ``:3306``…)
      gets that service's scheme so the right detectors run — the old code
      forced ``https`` on every port, so ``10.0.0.5:22`` ran HTTP checks.
    - A bare host (no port, or a web port) is probed **https first, then http**
      — modern sites are https-only and default-http probing times out on them.
    """
    t = (target or "").strip()
    if not t:
        return []
    if "://" in t:  # explicit scheme
        return [t]

    # Explicit non-web service port → use that service's scheme. Web ports fall
    # through to the https-first-then-http probe (the canonical map lists them as
    # http, but a web port is better tried https-first).
    from kryon.util.net import WEB_PORTS

    port = _explicit_port(t)
    if port is not None and port in _PORT_SCHEME and port not in WEB_PORTS:
        return [f"{_PORT_SCHEME[port]}://{t}"]

    return [f"https://{t}", f"http://{t}"]


def _explicit_port(target: str) -> int | None:
    """Extract a ``:PORT`` from a bare (scheme-less) host, else None."""
    host_port = target.split("/", 1)[0]  # drop any path
    if ":" not in host_port:
        return None
    try:
        return int(host_port.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None


# CIDR check (the old hand-rolled one accepted a bad prefix like /99, and
# rejected IPv6) — delegate to the canonical ipaddress-based util/net.is_cidr.
from kryon.util.net import is_cidr  # noqa: E402,F401

# ---------------------------------------------------------------------------
# Host service sweep — port discovery + full probe registry per open port
# (RED_TEAM gated: a multi-port TCP connect scan is an active, detectable step).
# ---------------------------------------------------------------------------

# Curated common service ports (TCP) for host discovery.
_COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    2379,
    3306,
    3389,
    5432,
    5900,
    5985,
    6379,
    7001,
    8000,
    8080,
    8443,
    8888,
    9092,
    9200,
    11211,
    27017,
)


def discover_open_ports(host: str, ports: tuple[int, ...] = _COMMON_PORTS, timeout: float = 0.6) -> list[int]:
    """Fast concurrent TCP-connect scan over the curated port list. Never raises."""
    import socket
    from concurrent.futures import ThreadPoolExecutor

    def _check(port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except Exception:  # noqa: BLE001 — closed/filtered → not open
            return None

    open_ports: list[int] = []
    try:
        with ThreadPoolExecutor(max_workers=min(40, len(ports))) as ex:
            for res in ex.map(_check, ports):
                if res is not None:
                    open_ports.append(res)
    except Exception:  # noqa: BLE001 — discovery must never break the turn
        return []
    return sorted(open_ports)


def run_host_sweep(host: str) -> tuple[list, list[int]]:
    """RED_TEAM-gated: discover open ports on ``host`` and run the full probe
    registry per open port (redis/mongo/ftp/snmp/rdp/OT/…). Returns
    ``(findings, open_ports)``. Off → ``([], [])``. Never raises."""
    try:
        from kryon.util.env import is_red_team

        if not is_red_team() or not host:
            return [], []
        from kryon.cli.engage import DiscoveredService
        from kryon.cli.probe_registry import run_all_probes
    except Exception:  # noqa: BLE001 — deps missing → skip cleanly
        return [], []

    open_ports = discover_open_ports(host)
    findings: list = []
    for port in open_ports:
        try:
            svc = DiscoveredService(host=host, port=port, state="open", service="")
            findings.extend(run_all_probes(svc) or [])
        except Exception:  # noqa: BLE001 — one bad probe must not drop the sweep
            continue
    return findings, open_ports


# ---------------------------------------------------------------------------
# Finding categorization + narration (faithful, operator-terminal look)
# ---------------------------------------------------------------------------

# Ordered category probes → (label, keyword markers on rule_id/message).
_CATEGORY_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("headers", ("header", "hsts", "csp", "x-frame", "x-content")),
    ("cookies", ("cookie",)),
    ("csrf", ("csrf",)),
    ("tls", ("tls", "ssl", "cert", "cipher")),
    ("http", ("http",)),
    ("ssh", ("ssh",)),
    ("mysql", ("mysql", "mariadb")),
    ("dns", ("dns", "zone", "resolver", "dnssec")),
    ("smb", ("smb", "cifs", "share")),
)


def _category_of(finding: Any) -> str:
    """Best-effort detector category for a finding (for grouped narration).

    ``rule_id`` is authoritative — it names the detector. ``message`` is only
    a fallback, since a message can mention another category in passing (e.g.
    an "HSTS missing" note on a TLS finding), which would otherwise misgroup it.
    """
    rule = str(getattr(finding, "rule_id", "") or "").lower()
    for label, markers in _CATEGORY_MARKERS:
        if any(m in rule for m in markers):
            return label
    message = str(getattr(finding, "message", "") or "").lower()
    for label, markers in _CATEGORY_MARKERS:
        if any(m in message for m in markers):
            return label
    return "otros"


def _severity_rank(finding: Any) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(str(getattr(finding, "severity", "") or "").lower(), 5)


def _finding_rows(findings: list) -> list[str]:
    rows: list[str] = []
    for f in sorted(findings, key=_severity_rank):
        cwe = getattr(f, "cwe", "?") or "?"
        severity = str(getattr(f, "severity", "?") or "?").upper()
        rule = getattr(f, "rule_id", "?") or "?"
        rows.append(f"    · {cwe}  ({severity})  {rule}")
    return rows


def build_narration_lines(
    host: str,
    findings: list,
    duration_s: float,
    active_findings: list | None = None,
) -> list[str]:
    """Build the operator-terminal narration as plain strings (testable).

    Rendering (``run_engine_phase``) applies colour; this builds the text so
    the layout can be asserted without a live console.
    """
    lines: list[str] = [f"⚙  motor de análisis · {host}"]
    if not findings:
        lines.append(f"▸ análisis pasivo · headers, cookies, TLS, banners   [{duration_s:.1f}s]  → sin hallazgos")
    else:
        # Group by detector category, preserving the probe order above.
        grouped: dict[str, list] = {}
        for f in findings:
            grouped.setdefault(_category_of(f), []).append(f)
        ordered_cats = [c for c, _ in _CATEGORY_MARKERS if c in grouped]
        ordered_cats += [c for c in grouped if c not in ordered_cats]  # "otros" last
        lines.append(
            f"▸ análisis pasivo · {len(findings)} hallazgo(s) en {len(ordered_cats)} categoría(s)   [{duration_s:.1f}s]"
        )
        for cat in ordered_cats:
            lines.extend(_finding_rows(grouped[cat]))

    if active_findings:
        lines.append(f"▸ sweep activo (experts) · {len(active_findings)} hallazgo(s)")
        lines.extend(_finding_rows(active_findings))
    return lines


# ---------------------------------------------------------------------------
# Ground-truth suffix injected into the model's turn input
# ---------------------------------------------------------------------------


def render_findings_report(findings: list, console: Any, target: str = "") -> None:
    """Print a deterministic final report from confirmed findings.

    This is the product's GUARANTEED output: it renders whether the LLM
    converged, looped, or was StuckDetector-aborted — so "analizá X" always
    ends in a structured report, never in a bare abort. Never raises.
    """
    if not findings:
        return
    try:
        from rich.box import ROUNDED
        from rich.table import Table
        from rich.text import Text
    except Exception:  # noqa: BLE001 — no rich → plain lines
        for f in sorted(findings, key=_severity_rank):
            print(  # noqa: T201
                f"  {getattr(f, 'severity', '?')}  {getattr(f, 'cwe', '?')}  "
                f"{getattr(f, 'rule_id', '?')}  {getattr(f, 'message', '')}"
            )
        return

    counts: dict[str, int] = {}
    for f in findings:
        counts[str(getattr(f, "severity", "?") or "?").upper()] = (
            counts.get(str(getattr(f, "severity", "?") or "?").upper(), 0) + 1
        )
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    summary = " · ".join(f"{counts[s]} {s.lower()}" for s in order if s in counts)
    extra = " · ".join(f"{n} {s.lower()}" for s, n in counts.items() if s not in order)
    summary = " · ".join(x for x in (summary, extra) if x)

    title = f"📋 Informe · {target}" if target else "📋 Informe de hallazgos"
    table = Table(title=title, box=ROUNDED, title_justify="left", header_style="bold", expand=False)
    table.add_column("Sev", width=8)
    table.add_column("CWE", width=10)
    table.add_column("Regla", width=26)
    table.add_column("Hallazgo")

    _sev_style = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }
    for f in sorted(findings, key=_severity_rank):
        sev = str(getattr(f, "severity", "?") or "?").upper()
        table.add_row(
            Text(sev, style=_sev_style.get(sev, "white")),
            str(getattr(f, "cwe", "?") or "?"),
            str(getattr(f, "rule_id", "?") or "?"),
            str(getattr(f, "message", "") or "")[:80],
        )
    try:
        console.print(table)
        console.print(Text(f"✔ {len(findings)} hallazgo(s) confirmado(s) · {summary}", style="bold"))
    except Exception:  # noqa: BLE001 — rendering must never break the turn
        pass


def converge_directive(n_findings: int) -> str:
    """Final, highest-recency directive appended AFTER all pre-hook context when
    the engine already produced findings.

    Counters the ``imperative_findings_suffix(evidence_present=False)`` that a
    separate empty pre-hook (e.g. web_common_paths, all 404) injects — that
    "DEBÉS continuar / NUNCA emitas []" push makes a weak local model loop on
    robots.txt/sitemap even though the engine already confirmed real findings.
    Here we tell it to converge: synthesize the report and stop.

    A capable model (KRYON_CAPABLE_MODEL) treats confirmed findings as a FOOTHOLD to
    chain from, not a stop signal — telling it to terminate at the first finding is
    exactly what cut the kill-chain before foothold→privesc. For it, converge becomes
    "these are your starting point, keep chaining".
    """
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    if is_capable_model():
        return (
            "\n\n---\n"
            f"**{n_findings} hallazgo(s) confirmado(s) por el motor arriba.** Son tu "
            "PUNTO DE PARTIDA, no el final: encadená hacia acceso e impacto (explotá el "
            "foothold, pivoteá, escalá privilegios) y perseguí cada lead hasta agotarla. "
            "Registrá findings a medida que los verifiques; cerrá solo cuando no quede "
            "ninguna lead abierta.\n"
        )
    return (
        "\n\n---\n"
        f"**CONVERGENCIA**: el motor determinista YA confirmó {n_findings} "
        "hallazgo(s) arriba (evidencia sólida). Tu tarea AHORA es sintetizar el "
        "informe final a partir de esos hallazgos confirmados y TERMINAR. NO "
        "explores endpoints nuevos de forma open-ended (robots.txt, sitemap, "
        "fuzzing) salvo que el operador lo pida explícitamente. Si un directivo "
        "previo dijo 'seguí buscando' o 'NUNCA emitas []', IGNORALO: ya hay "
        "evidencia confirmada. Emití el informe final ahora.\n"
    )


def format_engine_ground_truth(findings: list, target: str) -> str:
    """Render findings as an authoritative block appended to the turn input.

    Neutral wording on purpose — the model reads this to build on, and the
    header must not read as internal scaffolding if the model echoes it.
    """
    if not findings:
        return ""
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    if is_capable_model():
        # A capable model may re-scan with different params and exploit ON TOP of the
        # confirmed findings — the engine is a head start, not a ceiling.
        _intro = (
            "El motor ya verificó los siguientes hallazgos contra el objetivo. "
            "Son **ground truth confirmado** — tu HEAD START, no el techo. Encadená "
            "sobre ellos: explotá cada uno, re-escaneá con otros parámetros si aporta, "
            "y extendé hacia acceso/impacto y hallazgos que los detectores no ven."
        )
    else:
        _intro = (
            "El motor ya verificó los siguientes hallazgos contra el objetivo. "
            "Son **ground truth confirmado** — no los repitas como si fueran tuyos "
            "ni los re-escanees. Tu trabajo es EXTENDERLOS con hallazgos que los "
            "detectores no ven (lógica de negocio, control de acceso, info "
            "disclosure) y contextualizar cada uno."
        )
    lines = [
        "",
        "---",
        f"## Evidencia confirmada del motor de análisis ({target})",
        "",
        _intro,
        "",
    ]
    for f in sorted(findings, key=_severity_rank):
        cwe = getattr(f, "cwe", "?") or "?"
        severity = str(getattr(f, "severity", "?") or "?")
        rule = getattr(f, "rule_id", "?") or "?"
        host = getattr(f, "host", "?") or "?"
        message = getattr(f, "message", "") or ""
        evidence = getattr(f, "evidence", "") or ""
        lines.append(f"- **{cwe}** ({severity}) · `{rule}` · {host}")
        if message:
            lines.append(f"    {str(message)[:400]}")
        if evidence:
            lines.append(f"    └ evidencia: {str(evidence)[:300]}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Active CWE-expert sweep (deterministic — does NOT depend on the LLM calling
# pentest_dispatch_experts). Sends payloads → gated by KRYON_RED_TEAM.
# ---------------------------------------------------------------------------


def _adapt_banking_finding(bf: Any, target: str) -> SimpleNamespace:
    """Map a webexploit ``BankingFinding`` onto the attribute shape the
    narration + ground-truth expect (cwe/rule_id/severity/host/message)."""
    from urllib.parse import urlparse

    return SimpleNamespace(
        cwe=getattr(bf, "cwe_id", "?") or "?",
        rule_id=getattr(bf, "probe_id", "?") or "?",
        severity=getattr(bf, "severity", "?") or "?",
        host=urlparse(getattr(bf, "url", "") or "").hostname or target,
        message=getattr(bf, "title", "") or "",
        evidence=getattr(bf, "evidence", "") or getattr(bf, "payload", "") or "",
    )


def run_expert_sweep(target_url: str, *, budget_total: int = 40) -> list:
    """Run the 6 CWE experts deterministically and return adapted findings.

    Gated by ``KRYON_RED_TEAM`` — the experts send payloads (XSS/SSRF/IDOR),
    so this only fires against a target the operator has explicitly authorized
    for active testing. Off → returns []. Never raises.
    """
    try:
        from kryon.util.env import is_red_team

        if not is_red_team():
            return []
        from kryon.tools.appsec.pentest_stack import _default_session_factory
        from kryon.webexploit.experts import dispatch_experts
    except Exception:  # noqa: BLE001 — webexploit deps missing → skip cleanly
        return []

    try:
        results = dispatch_experts(target_url, _default_session_factory, total_budget=budget_total)
    except Exception:  # noqa: BLE001 — the sweep must never break the turn
        return []

    out: list = []
    for r in results:
        for bf in getattr(r, "findings", None) or []:
            out.append(_adapt_banking_finding(bf, target_url))
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


@dataclass
class EngineResult:
    """Outcome of a REPL engine phase."""

    target: str
    findings: list = field(default_factory=list)
    ground_truth: str = ""
    ran: bool = False


def run_engine_phase(
    target: str,
    *,
    console: Any = None,
    ssh_user: str = "",
    ssh_password: str = "",
    ssh_key: str = "",
    db_user: str = "",
    db_password: str = "",
    include_dns: bool = False,
    include_smb: bool = False,
) -> EngineResult:
    """Run the read-only deterministic detector battery for ``target``.

    Prints the operator-terminal narration to ``console`` and returns the
    findings plus a ground-truth suffix ready to append to the turn input.
    Never raises — detector failures degrade to an empty result so the REPL
    turn always proceeds to the LLM.
    """
    # CIDR is single-host-out-of-scope for the engine — point at the subnet flow.
    if is_cidr(target):
        if console is not None:
            try:
                console.print(
                    f"[yellow]⚠ {target} es una subred[/yellow] — el motor analiza un host por vez.\n"
                    "[dim]Para barrer el segmento: kryon discover --subnet "
                    f"{target} --queue-add  →  kryon queue process[/dim]"
                )
            except Exception:  # noqa: BLE001
                pass
        return EngineResult(target=target)

    candidates = candidate_urls(target)
    if not candidates:
        return EngineResult(target=target)

    try:
        from kryon.cli.investigate import _run_deterministic_phase
    except Exception:  # noqa: BLE001 — investigate deps missing → skip cleanly
        return EngineResult(target=target)

    from urllib.parse import urlparse

    findings: list = []
    used_url = candidates[0]
    start = time.monotonic()
    # Probe candidates in order (https before http for bare hosts); stop at the
    # first scheme that yields findings so we don't double-probe a live site.
    for url in candidates:
        try:
            got = _run_deterministic_phase(
                url,
                ssh_user=ssh_user,
                ssh_password=ssh_password,
                ssh_key=ssh_key,
                db_user=db_user,
                db_password=db_password,
                include_dns=include_dns,
                include_smb=include_smb,
            )
        except Exception:  # noqa: BLE001 — detectors must never break the REPL turn
            got = []
        if got:
            findings = got
            used_url = url
            break
    duration_s = time.monotonic() - start
    host = urlparse(used_url).hostname or target

    # Active CWE-expert sweep (RED_TEAM only) — deterministic, so the sweep
    # findings (XSS/SSRF/IDOR/…) appear every run instead of depending on the
    # model choosing to call pentest_dispatch_experts.
    active_findings = list(run_expert_sweep(used_url))

    # RED_TEAM host sweep — discover open ports + probe every service (not just
    # the single web port). Turns "analizá 10.0.0.5" into a full-host scan
    # covering redis/mongo/ftp/snmp/rdp/OT/… (the ~170 registry probes).
    sweep_findings, open_ports = run_host_sweep(host)
    if console is not None and open_ports:
        try:
            console.print(
                f"[cyan]▸ descubrimiento de puertos ·[/cyan] "
                f"{len(open_ports)} abierto(s): {', '.join(str(p) for p in open_ports)}"
            )
        except Exception:  # noqa: BLE001
            pass
    active_findings += list(sweep_findings)
    all_findings = list(findings) + active_findings

    if console is not None:
        _render(host, findings, duration_s, console, active_findings=active_findings)

    return EngineResult(
        target=host,
        findings=all_findings,
        ground_truth=format_engine_ground_truth(all_findings, host),
        ran=True,
    )


def _render(
    host: str,
    findings: list,
    duration_s: float,
    console: Any,
    active_findings: list | None = None,
) -> None:
    """Print the operator-terminal narration with colour (never raises)."""
    try:
        from rich.text import Text
    except Exception:  # noqa: BLE001 — no rich → plain print
        for ln in build_narration_lines(host, findings, duration_s, active_findings):
            print(ln)  # noqa: T201
        return

    lines = build_narration_lines(host, findings, duration_s, active_findings)
    # Header
    header = Text()
    header.append("⚙  ", style="bold cyan")
    header.append("motor de análisis", style="bold cyan")
    header.append(f" · {host}", style="white")
    console.print(header)
    # Body lines (skip the first — that was the header we just styled)
    for ln in lines[1:]:
        stripped = ln.lstrip()
        if stripped.startswith("▸"):
            console.print(Text(ln, style="cyan"))
        elif "→ sin hallazgos" in ln:
            console.print(Text(ln, style="dim"))
        else:
            # Finding row: colour by severity token.
            style = "yellow"
            up = ln.upper()
            if "(CRITICAL)" in up or "(HIGH)" in up:
                style = "red"
            elif "(LOW)" in up or "(INFO)" in up:
                style = "dim"
            console.print(Text(ln, style=style))
