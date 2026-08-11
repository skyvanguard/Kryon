"""Attack-path synthesis — grow a PROVEN AttackGraph from an engagement's
confirmed evidence and surface demonstrated low+low → critical chains.

XBOW's edge is chaining low-severity findings into a proven critical path,
*validating each link*. Kryon already had the graph primitives (``AttackGraph``:
capabilities, confirmed-only edges, BFS ``path_to`` / ``impact_paths``) but
nothing fed them a real chain — ``graph_from_facts`` built a flat ENTRY→cap
snapshot from 5 fact fields and ignored the richest offensive signals (confirmed
SQLi/privesc hints, confirmed findings). This module builds the graph from that
evidence:

  - a NODE is a capability (access, info, cred, admin, rce, db_takeover, …);
  - an EDGE is added ONLY when a deterministic detector CONFIRMED the move
    (``verification_level`` confirmed/judge-confirmed, not ``needs_verification``)
    — that is the "validate each link" contract, and it keeps this banca-safe
    (inferred/heuristic findings never fabricate a proven edge);
  - an impact finding whose precondition capability is already present chains
    FROM it, so two individually-low findings (e.g. CWE-200 info-leak feeding a
    CWE-639 IDOR) surface as one critical path.

Then ``impact_paths`` (BFS to an IMPACT_KIND) yields the demonstrated chains,
rendered for the reasoning prompt and the report. Pure + testable; no I/O, no LLM.
"""

from __future__ import annotations

import re

from kryon.intelligence.attack_graph import IMPACT_KINDS, AttackGraph, Capability, Edge

_CWE_RE = re.compile(r"(\d+)")

# Confirmed levels — only a proven edge may enter the graph.
_CONFIRMED_LEVELS = frozenset({"confirmed", "judge-confirmed"})

# CWE root → (precondition_kind, gained_kind, exploit_label).
# When a capability of `precondition_kind` already exists the edge chains FROM it
# (yielding a multi-hop low+low→critical path); otherwise it starts from `access`.
_CWE_EDGE: dict[str, tuple[str, str, str]] = {
    # impact-class exploits
    "89": ("access", "db_takeover", "sqli-dump"),
    "78": ("access", "rce", "command-injection"),
    "77": ("access", "rce", "command-injection"),
    "94": ("access", "rce", "code-injection"),
    "434": ("access", "rce", "malicious-upload"),
    "502": ("access", "rce", "insecure-deserialization"),
    "611": ("access", "data_exfil", "xxe"),
    "22": ("access", "data_exfil", "path-traversal"),
    "287": ("access", "admin", "auth-bypass"),
    "306": ("access", "admin", "auth-bypass"),
    # broken-access → account takeover; IDOR prefers to chain from leaked info
    "639": ("info", "account_takeover", "idor"),
    "566": ("access", "account_takeover", "broken-access-control"),
    "285": ("access", "account_takeover", "missing-authorization"),
    "862": ("access", "account_takeover", "missing-authorization"),
    # XSS: validate_xss confirms REFLECTION/execution, not a stolen session — so
    # it grants `session_risk` (a real capability) but NOT an IMPACT kind. It only
    # becomes account_takeover with additional proof (cookie sans HttpOnly + an
    # active session), which the confirmation alone doesn't establish. Honest: it
    # is "validado" but not "explotable" in the funnel.
    "79": ("access", "session_risk", "xss-reflected"),
    "918": ("access", "internal", "ssrf"),
    # low / info-class — grant an intermediate capability that impact edges chain from
    "200": ("access", "info", "info-exposure"),
    "538": ("access", "info", "info-exposure"),
    "215": ("access", "info", "info-exposure"),
    "319": ("access", "info", "cleartext-transport"),
    "1004": ("access", "info", "cookie-exposure"),
}


def _cwe_root(cwe: str) -> str:
    m = _CWE_RE.search(str(cwe or ""))
    return m.group(1) if m else ""


def cwe_reaches_impact(cwe: str) -> bool:
    """True when a CWE directly maps to an IMPACT capability (rce / db_takeover /
    account_takeover / admin / root / data_exfil). This is the "exploitable"
    classifier the funnel metric uses — a validated finding whose CWE reaches
    impact is *validated-exploitable* (XBOW), vs one that is merely confirmed
    (e.g. an info-leak / cookie flag, real but not a path to impact)."""
    spec = _CWE_EDGE.get(_cwe_root(cwe))
    return bool(spec and spec[1] in IMPACT_KINDS)


def is_proven(finding: object) -> bool:
    """A finding contributes a proven edge only if a detector confirmed it —
    the "validate each link" gate. Inferred/heuristic/needs-verification → no edge."""
    if bool(getattr(finding, "needs_verification", False)):
        return False
    level = str(getattr(finding, "verification_level", "confirmed") or "confirmed").lower()
    return level in _CONFIRMED_LEVELS


def _find_cap(graph: AttackGraph, kind: str, host: str = "", *, allow_cross_host: bool = True) -> Capability | None:
    """First capability of ``kind``. With a non-empty ``host`` it prefers a
    same-host match; ``allow_cross_host=False`` then FORBIDS falling back to a
    capability on a different host — so a finding on hostB never chains from an
    ``info`` leaked on hostA (which would fabricate a cross-host 'proven' chain).
    """
    kind = kind.lower()
    if host:
        for c in graph.capabilities():
            if c.kind.lower() == kind and c.host.lower() == host.lower():
                return c
        if not allow_cross_host:
            return None
    for c in graph.capabilities():
        if c.kind.lower() == kind:
            return c
    return None


def populate_attack_graph(g: AttackGraph, facts: object | None, findings: list | None) -> AttackGraph:
    """Add proven edges to an EXISTING graph from facts + CONFIRMED findings.

    Idempotent-safe (``AttackGraph.add_edge`` dedups identical edges), so it can
    be re-run each turn to fold in newly-accumulated facts WITHOUT clobbering the
    live edges the ``on_tool_end`` validation hook added between turns. Only
    confirmed findings create edges (validate-each-link).
    """
    findings = findings or []

    hosts: list[str] = [str(h) for h in (getattr(facts, "hosts", ()) or ())]
    for f in findings:
        h = str(getattr(f, "host", "") or "")
        if h and h not in hosts:
            hosts.append(h)
    primary_host = hosts[0] if hosts else ""

    # ENTRY → access(recon) for every host (the pivot every exploit builds on).
    access_cap = Capability("access", "recon", primary_host)
    g.add_edge(None, access_cap, "recon")
    for h in hosts[1:]:
        g.add_edge(None, Capability("access", "recon", h), "recon")

    # Confirmed findings → proven edges. Sort info-class first so an IDOR that
    # prefers to chain from `info` sees it already present.
    def _order(f: object) -> int:
        return 0 if _cwe_root(getattr(f, "cwe", "")) in {"200", "538", "215", "319", "1004"} else 1

    for f in sorted((x for x in findings if is_proven(x)), key=_order):
        spec = _CWE_EDGE.get(_cwe_root(getattr(f, "cwe", "")))
        if not spec:
            continue
        needs_kind, gains_kind, label = spec
        host = str(getattr(f, "host", "") or primary_host)
        src = _find_cap(g, needs_kind, host) or access_cap
        dst = Capability(gains_kind, "", host)
        ev = str(getattr(f, "message", "") or getattr(f, "cwe", ""))[:200]
        g.add_edge(src, dst, f"{getattr(f, 'cwe', '?')}:{label}", evidence=ev)

    # Facts-level chains the findings may not carry: creds (+ domain → admin/DA),
    # privesc hints → root, sqli-confirmed hint → db_takeover.
    creds = getattr(facts, "creds", ()) or ()
    domains = getattr(facts, "domains", ()) or ()
    if creds:
        user = creds[0][0] if isinstance(creds[0], (tuple, list)) and creds[0] else str(creds[0])
        cred_cap = Capability("cred", str(user), primary_host)
        g.add_edge(access_cap, cred_cap, "credential-capture")
        if domains:
            g.add_edge(cred_cap, Capability("admin", "", primary_host), "secretsdump/DA")

    for hint in getattr(facts, "hints", ()) or ():
        hs = str(hint)
        if hs.startswith("privesc:"):
            g.add_edge(access_cap, Capability("root", "", primary_host), hs)
        elif hs.startswith("sqli-confirmed"):
            g.add_edge(access_cap, Capability("db_takeover", "", primary_host), "sqli-confirmed")
    return g


def build_attack_graph(facts: object | None, findings: list | None) -> AttackGraph:
    """Build a fresh proven AttackGraph from facts + CONFIRMED findings (the
    post-hoc / report path). For the live loop use a persistent ``AttackGraph``
    grown by ``populate_attack_graph`` + ``add_confirmed_validation``."""
    return populate_attack_graph(AttackGraph(), facts, findings)


# ── Live confirm-then-add-edge (v2) ──────────────────────────────────────────
# When a validate_* tool CONFIRMS an exploit mid-run, record the proven edge the
# instant it happens — the literal "validate each link" moment — instead of only
# inferring edges post-hoc from the finished findings list.

# validate_* tool name → representative CWE root (mapped through _CWE_EDGE).
_VALIDATE_TOOL_CWE: dict[str, str] = {
    "validate_sqli": "89",  # → db_takeover
    "validate_rce": "78",  # → rce
    "validate_auth_bypass": "287",  # → admin
    "validate_xss": "79",  # → account_takeover (session/cookie theft)
}


def _parse_validation_status(output: object) -> str:
    """Extract ``validation_status`` from a validate_* tool result (JSON string).
    Returns '' if unparseable / absent."""
    import json

    text = str(output or "")
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return str(data.get("validation_status", "")).lower()
    except Exception:  # noqa: BLE001 — fall back to a substring probe
        pass
    low = text.lower()
    if '"validation_status": "confirmed"' in low or "'validation_status': 'confirmed'" in low:
        return "confirmed"
    return ""


def add_confirmed_validation(graph: AttackGraph, tool_name: object, output: object, *, host: str = "") -> bool:
    """Grow the persistent graph LIVE from a validate_* result. Adds a proven
    edge only when the tool CONFIRMED the exploit. Returns True if an edge was
    added. Safe/no-op for non-validation tools, non-confirmed verdicts, or
    unmapped CWEs — so it can be called on every tool result."""
    root = _VALIDATE_TOOL_CWE.get(str(tool_name or "").strip())
    if not root:
        return False
    if _parse_validation_status(output) != "confirmed":
        return False
    spec = _CWE_EDGE.get(root)
    if not spec:
        return False
    needs_kind, gains_kind, label = spec
    # Ensure an ENTRY→access pivot exists so BFS path_to() can reach the edge.
    access = _find_cap(graph, "access", host)
    if access is None:
        access = Capability("access", "recon", host)
        graph.add_edge(None, access, "recon")
    host = host or access.host
    src = _find_cap(graph, needs_kind, host) or access
    dst = Capability(gains_kind, "", host)
    return graph.add_edge(src, dst, f"CWE-{root}:{label} (live-validated)", evidence=str(output)[:200])


def confirmed_validation_finding(tool_name: object, output: object, *, host: str = "") -> dict[str, object] | None:
    """When a ``validate_*`` tool CONFIRMED an exploit, return a finding
    descriptor (``severity``/``detail``/``cwe``/``location``/``verified``) for a
    front-end to render + COUNT the exploit LIVE — closing the gap where only the
    deterministic phase streamed ``finding`` events and the model's loop
    confirmations merely bumped a counter. Returns ``None`` for a non-validation
    tool, a non-confirmed verdict, or an unmapped CWE.

    Pure: does NOT mutate the graph (``add_confirmed_validation`` owns that) and
    shares its exact gate, so the streamed finding and the proven graph edge stay
    in lock-step. Severity follows the funnel: a CWE that reaches an IMPACT
    capability is CRITICAL; a confirmed-but-intermediate exploit (e.g. XSS →
    session_risk, validated yet not itself account takeover) is HIGH.
    """
    root = _VALIDATE_TOOL_CWE.get(str(tool_name or "").strip())
    if not root:
        return None
    if _parse_validation_status(output) != "confirmed":
        return None
    spec = _CWE_EDGE.get(root)
    if not spec:
        return None
    _needs, _gains, label = spec
    cwe = f"CWE-{root}"
    return {
        "severity": "CRITICAL" if cwe_reaches_impact(cwe) else "HIGH",
        "detail": f"{label} confirmado ({tool_name})",
        "cwe": cwe,
        "location": host,
        "verified": True,
    }


def _render_chain(chain: list[Edge]) -> tuple[str, bool]:
    """Render 'access →[exploit] kind →[exploit] kind' and whether it is a
    multi-step (low+low→critical) chain (≥2 non-recon exploit edges)."""
    steps = []
    n_exploit = 0
    for e in chain:
        if e.exploit == "recon":
            continue
        n_exploit += 1
        steps.append(f"—[{e.exploit}]→ {e.dst[0]}")
    return ("access " + " ".join(steps)).strip(), n_exploit >= 2


def format_attack_paths(graph: AttackGraph) -> str:
    """Markdown block of demonstrated attack paths, or '' if none reached impact.
    Chains that traverse ≥2 confirmed exploits are tagged low+low→critical."""
    paths = graph.impact_paths()
    if not paths:
        return ""
    # de-dup identical renders (multiple impact caps can share a prefix)
    seen: set[str] = set()
    lines: list[str] = []
    for chain in paths:
        rendered, chained = _render_chain(chain)
        if rendered in seen:
            continue
        seen.add(rendered)
        tag = "  **(low+low→critical)**" if chained else ""
        lines.append(f"- {rendered}{tag}")
    return "\n".join(lines)


# ── v3 goal-directed path-pursuit ────────────────────────────────────────────
# Instead of "propose the best next action" (reactive), pick a TARGET impact,
# compute the residual gap against the capability-transition model, and drive the
# model to close the missing link. The template is the space of POSSIBLE moves
# (what an exploit COULD unlock), distinct from the proven graph (what actually
# fired) — pursuit reasons over the gap between held capabilities and impact.


def _transition_template() -> dict[str, list[tuple[str, str]]]:
    """Abstract capability-transition space: precondition_kind → [(gained_kind,
    exploit_label)]. Derived from the CWE→capability map + the facts-level chains,
    so the possible-moves graph stays in sync with what the builder can prove."""
    tmpl: dict[str, list[tuple[str, str]]] = {}
    for root, (pre, gain, label) in _CWE_EDGE.items():
        tmpl.setdefault(pre, []).append((gain, f"{label} (CWE-{root})"))
    tmpl.setdefault("cred", []).append(("admin", "secretsdump / DCSync"))
    tmpl.setdefault("access", []).append(("root", "privilege-escalation"))
    tmpl.setdefault("access", []).append(("cred", "credential-capture"))
    return tmpl


def plan_path_pursuit(graph: AttackGraph, target: str | None = None) -> str:
    """Goal-directed objective: from the capabilities already held, find a route
    to impact via the transition template (BFS) and name the first not-yet-proven
    link to pursue.

    ``target``: an operator-chosen impact kind (rce / admin / db_takeover / …) to
    pursue SPECIFICALLY; when None the NEAREST impact is chosen. Returns '' when
    impact is already reached, the target is invalid/unreachable, or no route
    exists. Deterministic (sorted traversal)."""
    goals = IMPACT_KINDS
    if target:
        t = target.strip().lower()
        if t not in IMPACT_KINDS:
            return ""  # unknown target → no directive (don't misdirect the model)
        if graph.has_capability(t):
            return ""  # the SPECIFIC target is already proven → done
        goals = frozenset({t})
    elif graph.impact_reached():
        # no pinned target → any impact reached means nothing left to pursue
        return ""
    held = {c.kind.lower() for c in graph.capabilities()}
    held.add("access")  # ENTRY always grants recon access
    tmpl = _transition_template()

    from collections import deque

    queue: deque[tuple[str, list[tuple[str, str, str]]]] = deque()
    seen = set(held)
    # Seed advanced capabilities FIRST (base `access` last) so pursuit prefers a
    # route that LEVERAGES prior progress (e.g. an already-leaked `info` → IDOR)
    # over starting a fresh hunt from access. Sorted within tiers → deterministic.
    for k in sorted(held, key=lambda x: (x == "access", x)):
        queue.append((k, []))
    route: list[tuple[str, str, str]] | None = None
    while queue:
        kind, path = queue.popleft()
        if kind in goals and path:
            route = path
            break
        for to, label in tmpl.get(kind, []):
            if to not in seen:
                seen.add(to)
                queue.append((to, path + [(kind, to, label)]))
    if not route:
        return ""
    frm, to, label = route[0]
    impact = route[-1][1]
    steps = len(route)
    chain = " → ".join(f"{f}→{t}" for f, t, _ in route)
    held_str = ", ".join(sorted(held))
    return (
        f"🎯 Path-pursuit — you hold [{held_str}]. Nearest impact: **{impact}** in "
        f"{steps} step(s) via {chain}. NEXT LINK to prove: from `{frm}` obtain "
        f"`{to}` using {label}. Pursue THIS specific link — do not re-recon."
    )
