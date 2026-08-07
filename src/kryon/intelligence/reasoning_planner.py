"""Reasoning-driven next-action planner — the XBOW headline capability.

The existing ``exploit_chain_planner`` picks the next move from ~70 hand-written
rules (first-match-wins): its ceiling is "how many pairs a human anticipated".
This module lets a capable model DRIVE instead: given the live attack-graph
state + extracted facts + what's been tried, it proposes the single best next
action — able to compose weaknesses no rule was written for (e.g. "the secret I
just leaked defeats that other endpoint's auth precondition").

Design, matching the project thesis (model reasons, determinism proves):
  - Gated by KRYON_CAPABLE_MODEL (``is_capable_model``). On a small local model
    the rules stay in charge; only a frontier model gets to drive.
  - The model is injected (``model_caller: prompt -> text``), so this is pure
    and testable; wiring a real caller is the runner's job.
  - The proposal is a *hypothesis*. The caller still executes it and confirms
    the resulting edge with the deterministic validators before adding it to
    the graph — the model never gets to assert an edge is real.
  - ``plan_hybrid`` composes it with the rules planner as a fallback, so this is
    strictly additive: reasoning first when enabled, rules otherwise.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from kryon.intelligence.attack_graph import AttackGraph
from kryon.intelligence.exploit_chain_planner import NextActionRecommendation
from kryon.util.env import is_capable_model

_JSON_BLOCK = re.compile(r"\{[^{}]*\"tool\"[^{}]*\}", re.DOTALL)


def summarize_findings(findings: list, *, cap: int = 12) -> str:
    """Compact list of confirmed weaknesses for the reasoning prompt, so the
    model chains FROM them (CWE-89 SQLi -> sqlmap dump -> creds -> auth bypass)
    instead of re-running recon. Duck-typed over engage/intelligence Finding."""
    if not findings:
        return ""
    parts: list[str] = []
    for f in findings[:cap]:
        cwe = str(getattr(f, "cwe", "") or "")
        host = str(getattr(f, "affected_asset", "") or getattr(f, "host", "") or "")
        title = str(getattr(f, "title", "") or getattr(f, "description", "") or "")[:80]
        seg = " ".join(x for x in (cwe, title) if x).strip()
        if host:
            seg = f"{seg} @ {host}" if seg else host
        if seg:
            parts.append(seg)
    return "; ".join(parts)


def _build_prompt(graph_summary: str, facts_summary: str, tried: list[str], findings_summary: str = "") -> str:
    tried_txt = "; ".join(tried[-12:]) if tried else "nothing yet"
    weak = (
        f"Confirmed weaknesses (CHAIN FROM THESE — exploit them, do NOT re-scan): {findings_summary}\n"
        if findings_summary
        else ""
    )
    return (
        "You are driving an authorized offensive engagement as an attack-path "
        "discoverer. Given the current state, propose the SINGLE best next "
        "action to extend the path toward real impact (RCE, admin, data "
        "exfiltration). Compose what you already have — a confirmed SQLi can be "
        "dumped for credentials; a leaked secret defeats another endpoint's "
        "auth; a user list enables a spray. Do NOT repeat what was already "
        "tried, and do NOT re-run recon when a weakness is already confirmed. "
        "When dumping via sqlmap, SCOPE the dump to the credentials table and "
        "columns (e.g. `-T Users -C email,password --dump`, add `--dbms=sqlite` "
        "if the back-end is known) so it completes — an unscoped `--dump` of "
        "every table times out before reaching the creds.\n\n"
        f"{weak}"
        f"Attack-graph state: {graph_summary}\n"
        f"Extracted facts: {facts_summary}\n"
        f"Already tried: {tried_txt}\n\n"
        "Answer ONLY with a JSON object: "
        '{"tool": "<tool name>", "args": "<literal args — use the REAL target '
        "host/URL from the facts above (e.g. the concrete host:port), NEVER a "
        'placeholder like <target> or HOST>", '
        '"rationale": "<why this advances the path>", "confidence": 0.0-1.0}. '
        "If there is no good next move, answer exactly: NONE."
    )


def _parse_action(text: str) -> NextActionRecommendation | None:
    if not text or text.strip().upper().startswith("NONE"):
        return None
    match = _JSON_BLOCK.search(text)
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    tool = str(obj.get("tool", "")).strip()
    args = str(obj.get("args", "")).strip()
    if not tool:
        return None
    try:
        confidence = float(obj.get("confidence", 0.7))
    except (TypeError, ValueError):
        confidence = 0.7
    confidence = max(0.0, min(1.0, confidence))
    return NextActionRecommendation(
        tool=tool,
        args=args,
        rationale=str(obj.get("rationale", "reasoning-driven next step")).strip()[:400],
        confidence=confidence,
    )


def propose_next_action(
    graph: AttackGraph,
    facts_summary: str,
    tool_history: list[str],
    model_caller: Callable[[str], str] | None,
    *,
    enabled: bool | None = None,
) -> NextActionRecommendation | None:
    """Ask a capable model for the next action from the live state.

    Returns None (caller should fall back to rules) when: reasoning is disabled
    (not a capable model), no model is available, or the model declines / emits
    an unparseable proposal.
    """
    if enabled is None:
        enabled = is_capable_model()
    if not enabled or model_caller is None:
        return None
    prompt = _build_prompt(graph.summary_for_prompt(), facts_summary, tool_history)
    try:
        reply = model_caller(prompt)
    except Exception:  # noqa: BLE001 — a model failure must not break planning
        return None
    return _parse_action(reply)


def plan_hybrid(
    graph: AttackGraph,
    facts_summary: str,
    tool_history: list[str],
    *,
    model_caller: Callable[[str], str] | None = None,
    rules_fallback: Callable[[], NextActionRecommendation | None] | None = None,
    enabled: bool | None = None,
) -> NextActionRecommendation | None:
    """Reasoning-first, rules-fallback. Strictly additive: with a small model
    (or no model) this is exactly the rules planner."""
    rec = propose_next_action(graph, facts_summary, tool_history, model_caller, enabled=enabled)
    if rec is not None:
        return rec
    return rules_fallback() if rules_fallback is not None else None
