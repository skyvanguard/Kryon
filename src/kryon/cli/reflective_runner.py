"""F203.C — Reflective Runner: autocrítica forzada cada N turns.

Wrapper sobre `Runner.run` que entre chunks de N turns inyecta una
"reflection turn" — un user message que fuerza al agent a auto-criticar.

Set KRYON_REFLECT_DEBUG=1 to see when reflection turns are injected
(prints to stdout, useful for debugging the loop).

F203.K — `ItemCaptureHooks` is a RunHooks subclass that captures
tool calls + outputs via `on_tool_start` / `on_tool_end` callbacks.
The capture list is shared across all chunks; even if a chunk hits
MaxTurnsExceeded (items lost from `result.new_items`), the hooks
already accumulated them. The final returned result exposes
`_captured_chain` attr that write_back_from_investigate prefers
over result.new_items extraction when it has more items.

Effect: writeback now works correctly even with reflect_every=3
(prev required reflect_every>=5 to avoid item loss). Validated
end-to-end: chain_len=6 captured vs chain_len=1 without hooks.

  1. ¿Qué APRENDÍ que NO sabía?
  2. ¿Qué HIPÓTESIS sigue sin verificar?
  3. ¿Estoy progresando o atascado?
  4. ¿Necesito una skill/tool que NO tengo?
  5. ¿Debería PARAR ahora?

Por qué: los LLMs locales (gpt-oss, kryon-14b) tienden a quedarse en
loops repetitivos. Yo (Claude) hago esto implícitamente — Kryon necesita
forzarlo via prompt injection.

**Stuck pattern detection**: si el agent invoca la misma tool con args
idénticos 2+ veces consecutivas, se considera "atascado" y la próxima
reflection turn emite un warning explícito antes de que el agent siga.

Banca-safe: el wrapper no introduce nuevas tools ni network calls,
solo modifica la conversation history entre chunks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from kryon.intelligence.exploit_chain_planner import (
    NextActionRecommendation,
    plan_next_action,
    render_for_prompt as _render_planner,
)
from kryon.intelligence.fact_extractor import (
    EMPTY as _EMPTY_FACTS,
    ExtractedFacts,
    extract_facts,
)
from kryon.intelligence.planner_runtime import (
    clear_current_state as _clear_planner_state,
    drain_planner_subcalls as _drain_planner_subcalls,
    init_planner_subcall_log as _init_planner_subcall_log,
    set_current_state as _set_planner_state,
)
from kryon.intelligence.tool_templates import (
    format_templates_for_recent_tools,
)

logger = logging.getLogger(__name__)


def _planner_autoexec_enabled() -> bool:
    """Tier 1.1 deterministic directive execution. DOUBLE-GATED, OFF by default:
    requires KRYON_PLANNER_AUTOEXEC=true AND an active red-team profile, so banking /
    passive runs never auto-fire an offensive directive."""
    from kryon.util.env import env_bool, is_red_team  # noqa: PLC0415

    return env_bool("KRYON_PLANNER_AUTOEXEC") and is_red_team()


# Default reflection cadence — every 4 turns (~3-4 tool calls).
_DEFAULT_REFLECT_EVERY = 4
# Stuck threshold: 2 identical (tool_name, args_hash) consecutive triggers warning.
_DEFAULT_STUCK_THRESHOLD = 2
# After this many CONSECUTIVE reflection chunks where _is_stuck keeps firing
# (same tool+args), abandon the loop. _is_stuck on its own only injects a
# warning into the reflection prompt — a weak agentic model ignores it and
# spins (observed: qwen3-8b re-fetching one URL ~48× to max_turns). This makes
# the warning escalate to a hard stop so the deterministic findings still
# surface instead of the budget burning on identical calls.
_DEFAULT_STUCK_ABORT_TRIGGER = 3
# F203.AX — intra-turn degeneracy detector. Catches n-gram repetition
# WITHIN a single reasoning block (Harmony analysis channel), which the
# turn-level _is_stuck can't see because no tool_call is emitted while
# the model spins in the loop. Observed empirically with gpt-oss-20b
# under reasoning_effort=medium against ambiguous tool outputs (e.g.
# smbclient -L returning only headers): the model repeats the same
# 10-50 word line 100+ times before the chunk's max_tokens cuts it off.
_DEFAULT_DEGEN_NGRAM_SIZE = 8
_DEFAULT_DEGEN_MIN_REPEATS = 4

# G7 (FASE 4) — stall detector window. Across this many consecutive
# reflection turns we check whether the planner kept emitting the same
# recommendation AND the ExtractedFacts signature didn't move. Both
# conditions together mean: the model is not following the planner
# AND new tool calls produced no new structured intel — i.e. it's
# spinning. Default 3 = three reflection turns with no progress
# before we emit a STALL block to the prompt.
_DEFAULT_STALL_THRESHOLD = 3

# FASE 8.B — operator-pair fallback. After this many CONSECUTIVE stall
# events the runner abandons the agent loop and surfaces a structured
# ``REQUEST_OPERATOR_INPUT`` summary so a human can take over via the
# REPL. The threshold is intentionally low (2) because by the time
# G7 fires once we already had three identical recommendations + no
# facts progress — two firings in a row means we're genuinely stuck
# and continuing wastes the run budget.
_DEFAULT_OPERATOR_PAIR_STALL_TRIGGER = 2


def _build_operator_input_request(
    facts: ExtractedFacts,
    next_action: NextActionRecommendation | None,
    recent_tool_history: list[_ToolCallRecord],
    turns_used: int,
) -> str:
    """FASE 8.B — render the ``REQUEST_OPERATOR_INPUT`` summary that
    replaces the run's final answer when the runner detects the
    agent is genuinely stuck (G7 stall fired ≥
    _DEFAULT_OPERATOR_PAIR_STALL_TRIGGER chunks in a row).

    The summary is markdown so the REPL can render it cleanly. It
    surfaces:
      - The planner's current directive (what the model SHOULD have
        run but didn't)
      - The ExtractedFacts snapshot (what we know so far)
      - The last 5 tool invocations (where the model drifted)
      - Concrete next-action suggestions the operator can copy

    The operator can then run the suggested command manually via
    the REPL or pivot to a different strategy.
    """
    parts: list[str] = [
        "\n🚨 **REQUEST_OPERATOR_INPUT** — agent stuck, human needed.\n",
        f"After {turns_used} turns the planner kept emitting the same "
        "high-confidence directive but the model wouldn't follow it "
        f"and ExtractedFacts didn't move for "
        f"{_DEFAULT_OPERATOR_PAIR_STALL_TRIGGER} consecutive stall "
        "windows. Continuing the autonomous loop wastes the budget. "
        "Take over manually via the REPL.\n",
    ]
    if next_action is not None:
        parts.append("\n## 🎯 Planner's last directive (run this if you agree)\n")
        parts.append(f"**Tool**: ``{next_action.tool}``\n")
        # Truncate args to keep the summary compact — full args are
        # in the history anyway.
        args_preview = next_action.args[:600]
        if len(next_action.args) > 600:
            args_preview += "..."
        parts.append(f"**Invocation**:\n```\n{args_preview}\n```\n")
        parts.append(f"**Rationale**: {next_action.rationale}\n")
        parts.append(f"**Confidence**: {next_action.confidence:.2f}\n")
    else:
        parts.append(
            "\n## 🎯 Planner has no recommendation for the current state\n\n"
            "The chain of rules abstained on the current ExtractedFacts. "
            "Either the target's class of exploit isn't covered by any "
            "encoded rule, or the current intel is too sparse to "
            "commit. Manual recon is the next move.\n"
        )

    if not facts.is_empty():
        parts.append("\n## 📊 Facts known so far\n")
        parts.append(facts.render_for_prompt())

    if recent_tool_history:
        parts.append("\n## 🔧 Last tool invocations (where the agent drifted)\n")
        for r in recent_tool_history[-5:]:
            preview = (r.args_preview or "")[:120]
            parts.append(f"- ``{r.tool_name}``: ``{preview}``")

    parts.append(
        "\n\n## ▶️ Suggested manual moves\n"
        "1. Run the planner directive above by hand and re-engage with "
        "``kryon investigate --resume`` once new intel is in.\n"
        "2. Open a shell into the container "
        "(``docker exec -it kryon bash``) and probe the target "
        "directly — the structured facts are ready for you to act on.\n"
        "3. If the target's exploit class isn't in any encoded rule, "
        "consider adding a new rule under "
        "``kryon.intelligence.exploit_chain_planner`` (the next CTF "
        "with this pattern will then plan automatically).\n"
    )
    return "\n".join(parts)


def _facts_signature(facts: Any) -> str:
    """Compact signature of an ExtractedFacts snapshot used by the
    stall detector to tell "facts moved" from "no progress". Counts
    high-value fields only — turn-by-turn version/hint changes are
    not enough to claim progress on their own."""
    if facts is None:
        return ""
    # Count ALL high-value fields, not just the original five — discovering a new
    # host / service / path / version IS progress, and omitting them made the stall
    # detector fire falsely while the agent was genuinely advancing on those axes.
    return (
        f"u={len(getattr(facts, 'users', ()))}"
        f"_h={len(getattr(facts, 'hashes', ()))}"
        f"_c={len(getattr(facts, 'creds', ()))}"
        f"_s={len(getattr(facts, 'shares', ()))}"
        f"_d={len(getattr(facts, 'domains', ()))}"
        f"_ho={len(getattr(facts, 'hosts', ()))}"
        f"_se={len(getattr(facts, 'services', ()))}"
        f"_pa={len(getattr(facts, 'paths', ()))}"
        f"_ve={len(getattr(facts, 'versions', ()))}"
    )


def _recommendation_signature(rec: Any) -> str:
    """Hashable signature of a NextActionRecommendation for the stall
    detector. Compares tool + args (truncated to 200 chars to absorb
    benign variation like a target IP substitution)."""
    if rec is None:
        return ""
    tool = getattr(rec, "tool", "") or ""
    args = (getattr(rec, "args", "") or "")[:200]
    return f"{tool}|{args}"


# FASE 11.B — premature summary detector. Pyrat bench B (qwen3-8b)
# emitted "📌 Resumen Ejecutivo" after only 3 tool calls and without
# confirming foothold. This catches that failure mode so the
# reflection turn can demand 3 hypotheses + a concrete next probe
# instead of letting the model give up.
_PREMATURE_SUMMARY_MARKERS = (
    # Spanish — the most common shape observed in qwen3-8b output.
    "Resumen Ejecutivo",
    "Resumen ejecutivo",
    "RESUMEN EJECUTIVO",
    "Resumen de la investigación",
    "Resumen de la Investigación",
    "Resumen Final",
    "Hallazgos:",
    "📋 Hallazgos",
    "Conclusión",
    "Conclusiones",
    # English — some skills are EN-only.
    "Executive Summary",
    "Investigation Summary",
    "## Findings",
    # Decorative variants observed in older runs.
    "═══ Resumen",
)
# Default threshold for "this chunk explored enough to justify a
# summary". 3 tool calls is the empirical floor: any less means the
# model saw at most 1-2 distinct probe results, which isn't enough
# to claim "no exploitable surface".
_DEFAULT_PREMATURE_THRESHOLD = 3
# Shell-prompt / foothold markers we look for inside facts.hints.
# Compiled once so the detector stays cheap to call.
_FOOTHOLD_HINT_REGEXES = (
    # Linux command exec evidence (id / whoami / getent).
    re.compile(r"\buid=\d+\b"),
    re.compile(r"\bgid=\d+\b"),
    # Shell prompt landed (user@host: or root@host:#).
    re.compile(r"\b(?:root|admin|administrator|www-data|nobody)@"),
    # Windows shell prompt.
    re.compile(r"[A-Z]:\\(?:Windows|Users|Program Files)", re.IGNORECASE),
    # FASE 11.J — Python REPL echo evidence. When the planner directive
    # ``printf 'print("kryon-probe")\n' | nc ...`` succeeds, the server
    # writes ``kryon-probe`` back to the socket. That IS foothold (the
    # remote end is executing arbitrary code we send) — same class of
    # control as a shell prompt. Pyrat bench 7 (2026-05-26) proved the
    # detector was treating this as "no foothold" because no shell
    # prompt landed, but the model had already gone on to invoke
    # ``os.system("id")`` over the same socket. Marker the REPL echo
    # so downstream gates (premature-summary, final rejection) treat
    # this as real foothold and don't fire on legitimate summaries
    # that follow the RCE chain.
    re.compile(r"\bkryon-probe\b"),
)


# FASE 11.N — recon-class threshold. CTFs that hinge on directory
# brute-force (gobuster cascade) and SSH bruteforce (hydra) chain
# through more tool calls than eval-class (REPL probe → exec).
# Bump the premature-summary threshold to give cascade rules room
# to land before the model's summary gets accepted.
_RECON_CLASS_PREMATURE_THRESHOLD = 5


def _count_real_tool_calls(records: list[_ToolCallRecord]) -> int:
    """FASE 11.N — count tool calls that represent NEW model-issued
    exploration, excluding synthetic ``planner_subcall`` records.

    The runner inserts ``planner_subcall`` records into tool_history
    so cascade rules' abstain checks can see the inner args of
    ``execute_planner_directive``. But those records reflect work
    the planner did *inside* the executor — they're not new probes
    the model picked. Counting them toward the premature-summary
    threshold lets a model that invoked ``execute_planner_directive``
    twice (each emitting one synthetic record) emit a summary as if
    it had done 4 explorations when it really did 2.

    Returns the count of records whose ``tool_name`` is NOT
    ``planner_subcall``.
    """
    return sum(1 for r in records if r.tool_name != "planner_subcall")


def _resolve_threshold_for_class(facts: ExtractedFacts) -> int:
    """FASE 11.N — pick the premature-summary threshold based on
    detected target class. Recon-class targets (web CTFs with
    robots.txt disallow hints) need more tool calls to chain
    through; eval-class targets (REPL ECHO confirmation) reach
    foothold with fewer.

    Class signal: presence of any ``disallow:<path>`` hint in
    ExtractedFacts.hints. That hint shape comes from
    fact_extractor's robots.txt parser (FASE 11.K) and uniquely
    identifies recon-class targets.

    Returns:
      _RECON_CLASS_PREMATURE_THRESHOLD (5) for recon-class targets,
      _DEFAULT_PREMATURE_THRESHOLD (3) otherwise.
    """
    has_disallow_hints = any(h.lower().startswith("disallow:") for h in facts.hints)
    if has_disallow_hints:
        return _RECON_CLASS_PREMATURE_THRESHOLD
    return _DEFAULT_PREMATURE_THRESHOLD


def _has_foothold(facts: ExtractedFacts) -> bool:
    """True when the agent has materially cracked past recon.

    Foothold = creds confirmed, hashes extracted, or shell-prompt
    evidence in hints. Knowing usernames or open ports alone is NOT
    foothold (that's recon, which doesn't justify ending an active
    pentest run).

    Conservative on purpose — false positives here would re-open the
    premature-summary loophole the detector is trying to close.
    """
    if facts.creds:
        return True
    if facts.hashes:
        return True
    for hint in facts.hints:
        for rx in _FOOTHOLD_HINT_REGEXES:
            if rx.search(hint):
                return True
    return False


# FASE 11.E — max times the runner will reject a premature final_output
# before letting it through. Default 2 strikes the balance: enough
# chances for the model to actually try alternatives (the FASE 11.B
# reflection prompt demands 3 hypotheses), but bounded so a genuinely-
# stuck model doesn't loop forever and the operator always sees SOME
# output. Override via ``KRYON_PREMATURE_MAX_REJECTIONS`` if needed.
_DEFAULT_PREMATURE_MAX_REJECTIONS = 2


def _detect_premature_summary(
    chunk_text: str,
    *,
    tool_calls_in_chunk: int,
    has_foothold: bool,
    threshold_tool_calls: int = _DEFAULT_PREMATURE_THRESHOLD,
) -> bool:
    """True when the model emitted an executive-summary marker without
    enough exploration evidence to justify ending the run.

    Three predicates must ALL hold:
      1. A summary marker appears anywhere in the chunk text.
      2. The chunk produced fewer than ``threshold_tool_calls`` tool
         calls (model gave up before exploring).
      3. ``has_foothold`` is False (no creds/hashes/shell yet).

    Any one missing → not premature. Catches the qwen3-8b "give up at
    turn 3" failure without false-positiving legitimate post-exploitation
    summaries.
    """
    if not chunk_text:
        return False
    if has_foothold:
        return False
    if tool_calls_in_chunk >= threshold_tool_calls:
        return False
    return any(marker in chunk_text for marker in _PREMATURE_SUMMARY_MARKERS)


def _evaluate_final_for_premature(
    final_output_text: str,
    *,
    tool_calls_in_chunk: int,
    has_foothold: bool,
    rejection_count: int,
    max_rejections: int = _DEFAULT_PREMATURE_MAX_REJECTIONS,
    threshold_tool_calls: int = _DEFAULT_PREMATURE_THRESHOLD,
) -> tuple[bool, str]:
    """FASE 11.E — gate the agent-finished path against premature summaries.

    Same predicate logic as ``_detect_premature_summary`` (summary marker
    + few tool calls + no foothold), plus a ``rejection_count``-bounded
    loop control so a genuinely-stuck model can't trap the runner in an
    infinite reject→retry→reject cycle.

    Returns a 2-tuple:
      - should_reject (bool): True means the caller should NOT return
        the result, inject the second-element message into the next
        reflection turn, and continue the chunk loop instead.
      - reflection_text (str): the imperative block to inject when
        rejecting; empty string when not rejecting.

    Why this exists: the Pyrat bench (2026-05-26) showed the model
    bypassing the FASE 11.B detector by emitting "Resumen Ejecutivo" as
    the agent's final_output instead of as intermediate reasoning. The
    pre-existing code path returned the result before the detector
    could see it. This gate closes that loophole.
    """
    # Cap reached — let the final through to avoid spinning forever.
    # The operator always sees SOMETHING even if it's premature; better
    # than a hung run.
    if rejection_count >= max_rejections:
        return False, ""

    is_premature = _detect_premature_summary(
        final_output_text,
        tool_calls_in_chunk=tool_calls_in_chunk,
        has_foothold=has_foothold,
        threshold_tool_calls=threshold_tool_calls,
    )
    if not is_premature:
        return False, ""

    attempt = rejection_count + 1
    msg = (
        f"\n🛑🛑🛑 **PREMATURE FINAL_OUTPUT REJECTED** (intento "
        f"{attempt}/{max_rejections}) 🛑🛑🛑\n\n"
        "Emitiste un resumen ejecutivo como respuesta final, pero NO "
        "exploraste lo suficiente: pocos tool calls, sin foothold "
        "confirmado (no creds, no hashes, no uid=, no shell prompt).\n\n"
        "**Tu resumen fue rechazado por el runner.** Tenés que probar "
        "alternativas antes de cerrar la run.\n\n"
        "Hard ask para este turn:\n"
        "  1. Generá **3 hipótesis** distintas sobre por qué la última "
        "respuesta del target fue ambigua / vacía / con error. "
        "(NO repitas las hipótesis del razonamiento previo.)\n"
        "  2. Para cada hipótesis, formulá UN tool call concreto que la "
        "probaría (línea exacta, no narres).\n"
        "  3. Ejecutá la hipótesis más prometedora AHORA con un tool "
        "call. NO emitas otro resumen sin confirmar RCE / creds / dump "
        "de DB / foothold equivalente.\n\n"
        f"Te quedan {max_rejections - attempt} intentos antes de que el "
        "runner deje pasar tu resumen igual. Usá este turn para hacer "
        "una probe real, no para reformular el mismo resumen.\n"
    )
    return True, msg


def _is_stall(
    recent_recs: deque,
    prev_facts_sig: str,
    current_facts_sig: str,
    threshold: int = _DEFAULT_STALL_THRESHOLD,
) -> bool:
    """G7 — true when the planner has emitted the same non-empty
    recommendation ``threshold`` times in a row AND the facts haven't
    moved between the first and last of those reflections.

    Conservative: bail out (False) unless we have a clear repeat AND a
    clear absence of progress. Both signals individually can be
    legitimate — a single repeat could be a brief retry; facts being
    static for one turn could be a transport hiccup. Together they're
    diagnostic.
    """
    if len(recent_recs) < threshold:
        return False
    first = recent_recs[0]
    if not first:  # empty recommendation slots don't count as a stall
        return False
    if any(r != first for r in recent_recs):
        return False
    # Facts moved between the prior signature snapshot and now? If so
    # the model IS making progress despite repeating the recommendation
    # — don't flag stall.
    if prev_facts_sig != current_facts_sig:
        return False
    return True


@dataclass(frozen=True)
class _ToolCallRecord:
    """One tool invocation observed in the agent's history."""

    tool_name: str
    args_hash: str
    args_preview: str  # first 200 chars for the prompt


def _hash_args(args_obj: Any) -> str:
    """Stable short hash of tool args. Used for stuck-pattern detection."""
    try:
        serialized = json.dumps(args_obj, sort_keys=True, default=str)
    except (TypeError, ValueError):
        serialized = repr(args_obj)
    return hashlib.sha1(serialized.encode("utf-8")).hexdigest()[:12]


def _extract_tool_calls(new_items: list[Any]) -> list[_ToolCallRecord]:
    """Pull tool call records from RunResult.new_items.

    The SDK uses ItemHelpers with tool_call_item / function_call_item
    types — we duck-type to avoid hard coupling: any item with both
    `name` and `arguments` (or `args`) attributes counts.
    """
    records: list[_ToolCallRecord] = []
    for item in new_items:
        # Different item shapes across SDK versions. Try the common ones.
        raw_item = getattr(item, "raw_item", None) or item

        # Try tool_name extraction across known shapes.
        tool_name: str | None = None
        if hasattr(raw_item, "name") and getattr(raw_item, "name", None):
            tool_name = str(raw_item.name)
        elif hasattr(raw_item, "tool_name") and getattr(raw_item, "tool_name", None):
            tool_name = str(raw_item.tool_name)
        else:
            fn = getattr(raw_item, "function", None)
            if isinstance(fn, dict) and fn.get("name"):
                tool_name = str(fn["name"])

        if not tool_name:
            continue

        # Try args extraction
        args_obj: Any = None
        if hasattr(raw_item, "arguments") and getattr(raw_item, "arguments", None) is not None:
            args_obj = raw_item.arguments
        elif hasattr(raw_item, "args") and getattr(raw_item, "args", None) is not None:
            args_obj = raw_item.args
        else:
            fn = getattr(raw_item, "function", None)
            if isinstance(fn, dict) and "arguments" in fn:
                args_obj = fn["arguments"]
        if args_obj is None:
            args_obj = {}

        records.append(
            _ToolCallRecord(
                tool_name=tool_name,
                args_hash=_hash_args(args_obj),
                args_preview=str(args_obj)[:200],
            )
        )
    return records


def _is_stuck(history: list[_ToolCallRecord], threshold: int) -> _ToolCallRecord | None:
    """Detect if the last N tool calls are identical (tool_name + args).

    Returns the repeated record, or None if not stuck.
    """
    if len(history) < threshold:
        return None
    tail = history[-threshold:]
    first = tail[0]
    if all(r.tool_name == first.tool_name and r.args_hash == first.args_hash for r in tail):
        return first
    return None


def _build_reflection_prompt(
    *,
    turns_used: int,
    total_turns_cap: int,
    tool_history: list[_ToolCallRecord],
    last_output_summary: str,
    stuck_record: _ToolCallRecord | None,
    degen_pattern: str | None = None,
    extracted_facts: ExtractedFacts | None = None,
    next_action: NextActionRecommendation | None = None,
    stall_detected: bool = False,
    premature_summary_detected: bool = False,
) -> str:
    """Compose the reflection user-message injected between chunks."""
    # Top distinct tools (most recent up to 6)
    recent_tools = list({r.tool_name for r in tool_history[-8:]})

    stuck_block = ""
    if stuck_record is not None:
        stuck_block = (
            f"\n⚠️ **STUCK PATTERN DETECTED**: invocaste `{stuck_record.tool_name}` "
            f"con args idénticos al menos 2 veces consecutivas.\n"
            f"   args preview: `{stuck_record.args_preview}`\n"
            f"   → Cambiá de approach. Opciones:\n"
            f"     • Invocá `tool_search(query='...')` para descubrir otra tool "
            f"del inventario (F203.E).\n"
            f"     • Invocá `request_skill(topic=...)` para obtener metodología "
            f"específica (F203.D).\n"
            f"     • Emití el resumen final si no hay más signal disponible.\n"
        )

    # F203.AX — intra-turn degeneracy block. Goes ABOVE the normal
    # reflection because the model needs to break the loop before any
    # reasoning continues. Phrased as a hard directive — empirical
    # tests with soft phrasing showed the model rationalizing the loop.
    degen_block = ""
    if degen_pattern:
        preview = degen_pattern[:200]
        degen_block = (
            f"\n🚨🚨🚨 **INTRA-TURN DEGENERACY DETECTED** 🚨🚨🚨\n\n"
            f"Tu razonamiento anterior REPITIÓ la siguiente secuencia "
            f"{_DEFAULT_DEGEN_MIN_REPEATS}+ veces:\n"
            f"   `{preview}`\n\n"
            f"**ESTO ES UN LOOP DEGENERADO. PARÁ DE REPETIR.**\n\n"
            f"Hacé EXACTAMENTE UNA de estas dos cosas:\n"
            f"  (A) **EMITÍ EL RESUMEN FINAL AHORA** con lo que tenés — "
            f"  enumerá los hallazgos concretos observados hasta aquí, sin "
            f"  esperar más datos.\n"
            f"  (B) **Una única nueva tool call** con args DISTINTOS a todo "
            f"  lo que ya hiciste. NO `smbclient -L` otra vez. NO `nmap` "
            f"  otra vez. Probá `nxc ldap`, `ldapsearch -x -b dc=...`, "
            f"  `GetNPUsers.py`, o `bloodhound-python` si todavía no los usaste.\n\n"
            f"NO ESCRIBAS más reasoning sobre el output que ya viste. "
            f"NO digas 'maybe' / 'already' / 'not' otra vez.\n"
        )

    # FASE 1 (G1+G2) — render structured facts block when present. Goes
    # BELOW the degeneracy block but ABOVE the generic reflection so the
    # model reads facts before reasoning about next steps.
    facts_block = ""
    if extracted_facts is not None and not extracted_facts.is_empty():
        facts_block = extracted_facts.render_for_prompt() + "\n"

    # FASE 2 (G3) + FASE 3 (G4) — render concrete next-action recommendation
    # when the planner had enough signal to emit one.
    #
    # G4 ordering fix: HIGH-confidence directives go to the very top of
    # the reflection message (above degen, facts, everything). The Pyrat
    # run #10 showed that even with the recommendation present the model
    # would prefer its own debugging chain when the block was buried
    # below other content. Position 1 + hard-imperative phrasing forces
    # the model to read it before any other context can re-anchor its
    # reasoning. LOW-confidence stays below facts (its softer phrasing
    # respects the model's discretion).
    next_action_block = ""
    next_action_top = ""
    if next_action is not None:
        # G4: substitute <target> placeholder with the first concrete host
        # we extracted (typically from web_fetch_smart final_url). When no
        # host is known yet the placeholder stays — the model can still
        # fill it from context.
        target_host = ""
        if extracted_facts is not None and extracted_facts.hosts:
            target_host = extracted_facts.hosts[0]
        rendered = _render_planner(next_action, target_host=target_host) + "\n"
        if next_action.confidence >= 0.85:
            next_action_top = rendered
        else:
            next_action_block = rendered

    # FASE 5 — canonical tool invocation templates. Sister to G5: where
    # G5 (anti-pattern hints) surfaces in facts.hints AFTER a misfire,
    # this block surfaces the right flag set BEFORE the next call.
    # Driven by ``tool_history`` so it only mentions tools the model
    # has actually been using.
    templates_block = ""
    try:
        recent_args = [r.args_preview for r in tool_history[-8:]]
        templates_block = format_templates_for_recent_tools(recent_args)
    except Exception:  # noqa: BLE001 — best-effort, never bubble
        templates_block = ""

    # G7 (FASE 4) — stall block. Emitted when the planner has been
    # repeating the same recommendation for N reflection turns AND
    # ExtractedFacts hasn't moved. Goes right BELOW the operator
    # directive (which the model is failing to follow) so the directive
    # context is still fresh when the stall warning lands.
    stall_block = ""
    if stall_detected:
        stall_block = (
            "\n🛑🛑🛑 **STALL DETECTED — model is not following the directive** 🛑🛑🛑\n\n"
            "You've been re-issuing the same kind of probe for "
            f"{_DEFAULT_STALL_THRESHOLD}+ reflection turns and no new "
            "structured intel has appeared in ExtractedFacts. This "
            "means: either you keep emitting variants of the wrong "
            "tool call (look at the OPERATOR DIRECTIVE above and "
            "copy it EXACTLY this time), or the target is genuinely "
            "unreachable / not exploitable through this path.\n\n"
            "Hard ask for THIS reflection turn:\n"
            "  (A) **Copy the OPERATOR DIRECTIVE verbatim** as your "
            "next tool call. No flag iteration, no path variation. "
            "Letter-for-letter copy.\n"
            "  (B) If you genuinely believe (A) cannot work, **emit "
            "the final summary now** with: (1) what you tried, (2) "
            "what each attempt returned, (3) the specific reason "
            "the directive cannot apply. Operator will decide next.\n"
        )

    # FASE 11.B — premature-summary block. Goes ABOVE facts because the
    # model just demonstrated it's NOT reading the facts at the bottom
    # of the prompt (otherwise it wouldn't have summarized). Mirrors
    # the imperative tone of the degeneracy + stall blocks — empirical
    # tests with soft phrasing let the model rationalize the early
    # exit. Hard directive: "NO TERMINES" + 3-hypothesis demand.
    premature_block = ""
    if premature_summary_detected:
        premature_block = (
            "\n🛑🛑🛑 **PREMATURE SUMMARY DETECTED** 🛑🛑🛑\n\n"
            "Emitiste un 'Resumen Ejecutivo' / 'Hallazgos' / 'Conclusión' "
            "después de muy pocos tool calls y SIN haber confirmado "
            "foothold real (no hay creds, hashes, uid=, ni shell prompt "
            "en los facts extraídos).\n\n"
            "**NO TERMINES AÚN. El target todavía no fue probado de "
            "verdad.**\n\n"
            "Hard ask para este turn:\n"
            "  1. Generá **3 hipótesis** distintas sobre por qué la última "
            "respuesta del target fue ambigua / vacía / con error.\n"
            "  2. Para cada hipótesis, formulá UN tool call concreto que "
            "la probaría (no narres — escribí la línea exacta).\n"
            "  3. Ejecutá la hipótesis más prometedora AHORA. NO regreses "
            "al resumen hasta confirmar RCE, creds, dump de DB, o foothold "
            "equivalente.\n\n"
            "Recordá: el objetivo del operator pidió pentest activo, no "
            "recon pasivo. Un resumen prematuro = run perdida.\n"
        )

    return (
        f"\n---\n## 🪞 Reflection turn (turn {turns_used}/{total_turns_cap})\n\n"
        f"{next_action_top}"
        f"{premature_block}"
        f"{stall_block}"
        f"{degen_block}"
        f"{facts_block}"
        f"{next_action_block}"
        f"{templates_block}"
        f"Tools recientes usadas: {recent_tools or 'ninguna'}\n"
        f"Última observación (preview):\n```\n{last_output_summary[:500]}\n```\n"
        f"{stuck_block}\n"
        f"**Antes de continuar**, respondé internamente (no necesitás emitir mensaje "
        f"separado — guialo en tu razonamiento del próximo turn):\n\n"
        f"1. ¿Qué **aprendí** en estos últimos turns que NO sabía antes?\n"
        f"2. ¿Qué **hipótesis** sigue sin verificar?\n"
        f"3. ¿Estoy **progresando** hacia el objetivo? (sí / no / atascado)\n"
        f"4. ¿Necesito una **skill o tool** que no tengo? "
        f"(si sí, invocá `request_skill(topic='...')` para obtenerla)\n"
        f"5. ¿Debería **PARAR** ahora? (sí / no / por qué)\n\n"
        f"Si decidís parar → emití el resumen final del objetivo del operador.\n"
        f"Si no → continuá con el tool call que aporte MÁS signal nuevo, "
        f"NO repitas tools ya invocadas con los mismos args.\n"
    )


def _detect_intra_turn_degeneracy(
    text: str,
    *,
    ngram_size: int = _DEFAULT_DEGEN_NGRAM_SIZE,
    min_repeats: int = _DEFAULT_DEGEN_MIN_REPEATS,
) -> str | None:
    """Detect tight n-gram repetition within a single reasoning/output block.

    Operates on the raw text of one or more ModelResponses concatenated.
    Returns the offending n-gram (joined string) if degeneracy detected,
    None otherwise.

    Why this exists (F203.AX): the turn-level `_is_stuck` only fires when
    consecutive tool calls have identical (name, args_hash). gpt-oss-20b
    can degenerate INSIDE a single chunk, repeating a line of reasoning
    100+ times without ever emitting another tool_call. By the time the
    chunk's max_tokens kicks in, thousands of tokens are wasted and the
    next chunk has no good signal to act on. This detector catches it
    post-chunk so the reflective runner can inject an explicit
    "STOP REPEATING" reflection instead of normal cadence.

    Tuning rationale:
      ngram_size=8: long enough to skip common short phrases ("we need
        to") while still catching the multi-line repetitions seen in
        empirical degeneracy logs.
      min_repeats=4: a 32-word block repeated 4 times = ~128 wasted
        tokens. Lower threshold risks false positives on legitimate
        enumeration narration ("found user X. found user Y. ...").
    """
    if not text:
        return None
    words = text.split()
    if len(words) < ngram_size * min_repeats:
        return None

    from collections import Counter

    ngrams = [" ".join(words[i : i + ngram_size]) for i in range(len(words) - ngram_size + 1)]
    if not ngrams:
        return None
    counts = Counter(ngrams)
    most_common, count = counts.most_common(1)[0]
    if count >= min_repeats:
        return most_common
    return None


def _chunk_text_from_capture(capture_hooks: Any) -> str:
    """B9 (FASE 2) — reconstruct a chunk-text string from ItemCaptureHooks
    when the SDK didn't return a usable ``result`` object (MaxTurnsExceeded
    branch).

    The hook records ``(tool, output_preview)`` for every tool invocation
    that fired inside the chunk. We render each as a ``▸ <tool>`` marker
    line + the captured preview so the same ``_extract_facts_from_chunk``
    splitter logic works on the reconstructed text.

    Without this, B9: when chunks hit max_turns repeatedly (common with
    gpt-oss-20b reasoning), the fact extractor + planner never ran and
    the model kept iterating blind. With this, both fire from
    captured-output reconstruction even on the unhappy path.
    """
    parts: list[str] = []
    items = getattr(capture_hooks, "captured_items", None) or []
    for item in items:
        if item.get("type") != "tool_call":
            continue
        tool_name = item.get("tool", "")
        output_preview = item.get("output_preview", "")
        if not tool_name or not output_preview:
            continue
        parts.append(f"\n▸ {tool_name}\n{output_preview}")
    return "".join(parts)


def _salvage_chunk_intel(capture_hooks: Any, accumulated_facts: Any, tool_history: list) -> Any:
    """Recover facts + planner subcalls from the in-flight capture when a chunk
    exits ABNORMALLY (timeout / server-500), so the next chunk isn't blind.

    The MaxTurns/Stuck paths already do this; timeout and 500 used to ``continue``
    and drop everything the chunk captured before dying — a model that ran useful
    tools and then hit a 500 lost that intel and re-explored from scratch. Mutates
    ``tool_history`` in place; returns the updated ``accumulated_facts``.
    """
    try:
        ct = _chunk_text_from_capture(capture_hooks)
        if ct:
            accumulated_facts = accumulated_facts.merge(_extract_facts_from_chunk(ct))
    except Exception as e:  # noqa: BLE001
        logger.debug("salvage facts failed: %s", e)
    try:
        for sub_args in _drain_planner_subcalls():
            tool_history.append(
                _ToolCallRecord(
                    tool_name="planner_subcall",
                    args_hash=_hash_args(sub_args),
                    args_preview=sub_args[:200],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.debug("salvage subcalls failed: %s", e)
    return accumulated_facts


def _extract_chunk_text(result: Any) -> str:
    """Concatenate the textual content of all ModelResponses in a chunk.

    Used by the intra-turn degeneracy detector. Covers two shapes:
      (a) `raw_responses` list of ModelResponse-like objects with
          `.message.content` (OpenAI chat completion shape).
      (b) `final_output` fallback when raw_responses is empty / opaque.

    Handles both string content and structured (list of dict) content
    used by some SDK versions.
    """
    parts: list[str] = []
    raw = getattr(result, "raw_responses", None) or []
    for r in raw:
        msg = getattr(r, "message", None) or r
        content = getattr(msg, "content", None)
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str):
                        parts.append(text)
                elif isinstance(item, str):
                    parts.append(item)
        # ModelResponse shape (the native default): the model's text lives in
        # `.output` message items, NOT `.message.content` (which is absent → the
        # old code fell straight to final_output, leaving the degeneracy detector
        # inert on every tool-calling turn). Pull text from message items only;
        # tool-call items carry no `.content`, so their args never pollute the
        # n-gram degeneracy signal.
        for out_item in getattr(r, "output", None) or []:
            oc = getattr(out_item, "content", None)
            if isinstance(oc, str):
                parts.append(oc)
            elif isinstance(oc, list):
                for c in oc:
                    t = getattr(c, "text", None) or (c.get("text") if isinstance(c, dict) else None)
                    if isinstance(t, str):
                        parts.append(t)
    if not parts:
        fo = getattr(result, "final_output", None)
        if fo:
            parts.append(str(fo))
    return "\n".join(parts)


# Regex that splits a Kryon chunk text on per-tool invocation markers.
# Each tool call renders as a line starting with the "▸" marker followed
# by the tool name + args. The output of that call sits between markers,
# so splitting on the marker isolates ``(invocation_line, output)`` pairs
# for the fact extractor to dispatch on.
#
# ``(?:^|\n)`` not plain ``\n`` so we still catch the first invocation
# when it sits at the very start of the chunk (no leading newline).
_TOOL_MARKER_RE = re.compile(r"(?:^|\n)▸\s+", flags=re.UNICODE)


def _extract_facts_from_chunk(chunk_text: str) -> ExtractedFacts:
    """FASE 1 (G1+G2) — pull structured facts from one chunk's text.

    The chunk text concatenates the model's reasoning AND tool outputs
    as they appeared in the rendered transcript. The renderer marks each
    tool invocation with the "▸" prefix, so we split on that marker and
    dispatch each (tool_invocation_line, output_block) pair to the
    per-tool parser. We also do a single generic pass over the whole
    text to pick up high-signal patterns (krb5 hashes, CTF hints) that
    may sit in the reasoning rather than in a tool-output block.

    Returns an accumulated ``ExtractedFacts`` for the chunk. Caller
    merges into the cross-chunk accumulator.
    """
    if not chunk_text:
        return _EMPTY_FACTS

    # Whole-chunk generic pass first — picks up hints/hashes that the
    # model may have echoed in its reasoning even if no tool produced
    # them directly.
    accum = extract_facts("", chunk_text)

    blocks = _TOOL_MARKER_RE.split(chunk_text)
    # blocks[0] is text before the first marker — already covered by
    # the generic pass above. Skip it.
    for block in blocks[1:]:
        first_line, _, rest = block.partition("\n")
        if not rest:
            continue
        accum = accum.merge(extract_facts(first_line, rest))

    return accum


def _has_pending_tool_calls(result: Any) -> bool:
    """Heuristic: did the last turn end with tool calls pending (not final answer)?

    We look at result.new_items — if the tail contains a tool_call without
    a matching tool_call_output, the agent expected to continue.
    Defensive: returns False on unknown shapes (caller treats False as
    'agent finished').
    """
    new_items = getattr(result, "new_items", None)
    if not new_items:
        return False
    # If final_output is set (non-None, non-empty), assume agent finished.
    final_output = getattr(result, "final_output", None)
    if final_output:
        return False
    return True


class ItemCaptureHooks:
    """F203.K — RunHooks subclass that captures tool calls + outputs
    in-flight, so we don't lose data when a chunk hit MaxTurnsExceeded.

    The SDK's `Runner.run` raises MaxTurnsExceeded WITHOUT returning a
    partial result — items executed in that chunk are lost from
    `result.new_items`. RunHooks fire ON EVERY tool invocation, so by
    accumulating into a shared list, we preserve the full history even
    across raised chunks.

    Duck-typed to match `kryon.sdk.agents.lifecycle.RunHooks` without
    importing it directly (avoids hard coupling — the runner accepts
    any object with the on_* methods).
    """

    def __init__(self) -> None:
        self.captured_items: list[dict[str, Any]] = []
        # Map tool name → last started index so on_tool_end can attach output
        self._last_call_idx: dict[str, int] = {}

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        pass

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        # Mark the agent's final output as a separate captured entry so
        # downstream consumers can identify "the end" vs intermediate
        # tool calls.
        self.captured_items.append(
            {
                "type": "agent_end",
                "output_preview": str(output)[:500] if output else "",
                "timestamp": time.time(),
            }
        )

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        pass

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        tool_name = getattr(tool, "name", None) or str(tool)
        entry = {
            "type": "tool_call",
            "tool": tool_name,
            "args": "",  # filled in on_tool_end if we get access
            "output_preview": "",
            "timestamp": time.time(),
        }
        self.captured_items.append(entry)
        self._last_call_idx[tool_name] = len(self.captured_items) - 1

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        tool_name = getattr(tool, "name", None) or str(tool)
        idx = self._last_call_idx.get(tool_name)
        if idx is not None and idx < len(self.captured_items):
            self.captured_items[idx]["output_preview"] = str(result)[:500]

    def to_chain(self) -> list[dict[str, Any]]:
        """Return captured items in chain schema (compatible with
        write_back_from_investigate._extract_chain output)."""
        return [
            {
                "tool": item["tool"],
                "args": item.get("args", ""),
                "output_preview": item.get("output_preview", ""),
            }
            for item in self.captured_items
            if item.get("type") == "tool_call"
        ]


async def run_with_reflection(
    agent: Any,
    initial_input: str | list[Any],
    *,
    reflect_every: int = _DEFAULT_REFLECT_EVERY,
    max_total_turns: int = 30,
    run_config: Any = None,
    stuck_threshold: int = _DEFAULT_STUCK_THRESHOLD,
) -> Any:
    """Run an agent with periodic reflection turn injection.

    Args:
        agent: The agent to run.
        initial_input: First user message or input_list.
        reflect_every: Inject reflection turn every N turns. 0 = disable
            (passthrough to Runner.run with max_turns=max_total_turns).
        max_total_turns: Hard cap across all chunks.
        run_config: SDK RunConfig (passed through to Runner.run).
        stuck_threshold: How many consecutive identical tool calls trigger
            STUCK pattern warning (default 2).

    Returns:
        The last RunResult from the final chunk.
    """
    from kryon.sdk.agents.run import Runner

    if reflect_every <= 0:
        # Passthrough — no reflection injection.
        return await Runner.run(
            agent,
            input=initial_input,
            max_turns=max_total_turns,
            run_config=run_config,
        )

    current_input: Any = initial_input
    turns_used = 0
    tool_history: list[_ToolCallRecord] = []
    last_result: Any = None
    # Tier-2 scaffolding telemetry: track whether the model FOLLOWS the high-confidence
    # planner directives we inject, or ignores them. Best-effort, opt-in flush.
    from kryon.intelligence.planner_adherence import AdherenceTracker  # noqa: PLC0415

    _adherence = AdherenceTracker()
    _adh_th_len = 0  # tool_history length at the last injection (to find the model's action)
    _autoexec_block = ""  # Tier 1.1: result of a deterministically-executed directive, injected next turn
    # F203.H — accumulate new_items across chunks so downstream consumers
    # (e.g. write_back_from_investigate) see the full tool call history,
    # not just the items from the last chunk.
    accumulated_items: list[Any] = []
    # F203.K — RunHooks-based capture: fires on EVERY tool invocation,
    # even when the chunk hit MaxTurnsExceeded. Shared across all chunks.
    capture_hooks = ItemCaptureHooks()
    # FASE 1 (G1+G2) — cross-chunk structured intel accumulator. The
    # model "forgets" what tools previously revealed when reflection
    # turns get long; injecting this block into every reflection keeps
    # the picture coherent across the chunked run.
    accumulated_facts: ExtractedFacts = _EMPTY_FACTS

    # G7 (FASE 4) — stall detector state. Tracks the last N
    # recommendations the planner emitted plus the facts signature at
    # the start of the window so we can tell "model isn't following
    # directive" from "model is making progress despite the repeat".
    recent_recs_window: deque = deque(maxlen=_DEFAULT_STALL_THRESHOLD)
    prev_facts_sig_for_stall: str = ""
    # FASE 8.B — count consecutive stall events. When we've fired the
    # stall block ``_DEFAULT_OPERATOR_PAIR_STALL_TRIGGER`` times in a
    # row without facts moving, the runner abandons the loop and
    # surfaces a REQUEST_OPERATOR_INPUT summary so a human takes over.
    consecutive_stall_count: int = 0
    # Count consecutive chunks where _is_stuck fires (same tool+args). Crossing
    # _DEFAULT_STUCK_ABORT_TRIGGER abandons the loop (see below).
    consecutive_stuck_count: int = 0
    operator_input_requested: bool = False
    operator_input_summary: str = ""

    # FASE 11.E — number of times the agent-finished path rejected a
    # premature final_output and forced reflection. Bounded by
    # _DEFAULT_PREMATURE_MAX_REJECTIONS (override via env). Counter
    # increments on each rejection; once it reaches the cap, the next
    # premature final is allowed through to avoid an infinite loop.
    premature_rejection_count: int = 0
    _max_rejections_env = os.environ.get("KRYON_PREMATURE_MAX_REJECTIONS", "")
    try:
        premature_max_rejections = (
            int(_max_rejections_env) if _max_rejections_env else _DEFAULT_PREMATURE_MAX_REJECTIONS
        )
    except ValueError:
        premature_max_rejections = _DEFAULT_PREMATURE_MAX_REJECTIONS

    # F1.5 — wall-clock budget guard-rail. Protege el saldo (perfil API) y evita
    # runs colgados: si el loop excede KRYON_WALL_BUDGET_S segundos, aborta limpio
    # entre chunks. 0/unset = sin límite (comportamiento previo).
    try:
        _wall_budget_s = float(os.environ.get("KRYON_WALL_BUDGET_S") or 0)
    except ValueError:
        _wall_budget_s = 0.0
    _loop_start = time.monotonic()
    # Per-chunk timeout. The wall budget only checks BETWEEN chunks, so a single
    # hung chunk (stuck tool or a tight loop in the agent step) never returns and
    # the loop never terminates. wait_for around each chunk guarantees progress.
    #
    # IMPORTANT: this exists to break GENUINELY hung chunks, NOT slow-but-working
    # generation. The local MoE (~1 tok/s) legitimately takes minutes per chunk,
    # so the old 180s default false-positived — it killed the run after 2 chunk
    # timeouts before the model produced ANY output (observed live). So: default
    # generous for local LLMs, and never fire before the wall budget (the real
    # overall guard). Operators still override via KRYON_CHUNK_TIMEOUT_S.
    _is_local_llm = os.environ.get("KRYON_LOCAL_LLM", "").strip().lower() in ("1", "true", "yes")
    _default_chunk_timeout = 900.0 if _is_local_llm else 180.0
    try:
        _chunk_timeout_s = float(os.environ.get("KRYON_CHUNK_TIMEOUT_S") or _default_chunk_timeout)
    except ValueError:
        _chunk_timeout_s = _default_chunk_timeout
    if _wall_budget_s > 0:
        # The wall budget bounds the whole run; the chunk timeout must not pre-empt it.
        _chunk_timeout_s = max(_chunk_timeout_s, _wall_budget_s)
    _chunk_timeouts = 0
    _MAX_CHUNK_TIMEOUTS = 2
    # A local model can emit a tool_call whose JSON arguments are malformed
    # (e.g. an SSH key inlined with raw newlines + quotes), which the llama.cpp
    # server rejects with HTTP 500 "Failed to parse tool call arguments". That
    # used to kill the whole run one step from a foothold. Treat it as a
    # recoverable per-chunk fault: nudge the model to stop inlining large
    # payloads, retry, and give up after a few failures. COST GUARD: each retry
    # re-processes the full prompt (~tens of K tokens), so the cap is low AND we
    # bail immediately if the model re-emits the SAME error despite the nudge
    # (a stubborn local model won't change — retrying just burns tokens/$).
    _server_errors = 0
    _MAX_SERVER_ERRORS = 3
    _last_500_fingerprint: str | None = None

    while turns_used < max_total_turns:
        if _wall_budget_s and (time.monotonic() - _loop_start) > _wall_budget_s:
            logger.warning(
                "F1.5 wall-clock budget %.0fs exceeded (turns_used=%d) — aborting loop",
                _wall_budget_s,
                turns_used,
            )
            break
        chunk_size = min(reflect_every, max_total_turns - turns_used)
        if chunk_size <= 0:
            break

        # FASE 6 — set the planner ContextVar BEFORE the chunk runs so
        # any ``execute_planner_directive`` invocation the model makes
        # during this chunk has live state to read. Previously this was
        # set only AFTER each chunk completed, which meant the tool
        # returned ``[NO RUNTIME]`` on the very first invocation (the
        # state hadn't been written yet). Bug surfaced empirically in
        # the Pyrat run #15b log.
        try:
            _set_planner_state(
                accumulated_facts,
                [r.args_preview for r in tool_history],
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("planner runtime state pre-set failed: %s", e)

        # FASE 11.M — prime the sub-call log to an empty list in the
        # CURRENT context so the executor (which may run in a child
        # asyncio task whose ContextVar writes don't propagate back)
        # sees a list ref it can append to without calling
        # ``ContextVar.set``. The first bench iteration of FASE 11.M
        # (Robots bench 20) had record_planner_subcall calling
        # ``_subcall_log.set()`` from inside the executor's task,
        # which produced a child-private view the runner never saw —
        # zero sub-call records made it into tool_history. Priming
        # to ``[]`` here, combined with the in-place-only mutation
        # invariant on the executor side, fixes the propagation.
        try:
            _init_planner_subcall_log()
        except Exception as e:  # noqa: BLE001
            logger.debug("planner subcall log init failed: %s", e)

        # F-CTXMGMT — trim accumulated tool outputs in the history BEFORE each
        # chunk so a long engagement doesn't snowball the context. Observed live:
        # a 44-min web pentest grew the history to ~20K tokens, and Devstral (24B
        # dense) re-processed all of it per turn → minutes/turn, GPU pinned. This
        # was wired into the REPL but NOT the investigate loop. micro_compact
        # keeps recent messages intact + head/tail of OLD large tool outputs.
        # Kill-switch: KRYON_MICRO_COMPACT=false.
        if os.environ.get("KRYON_MICRO_COMPACT", "true").strip().lower() != "false":
            try:
                model = getattr(agent, "model", None)
                if model is not None and hasattr(model, "message_history"):
                    from kryon.services.micro_compact import micro_compact_history

                    _trimmed = micro_compact_history(model.message_history)
                    if _trimmed:
                        logger.debug("micro-compact trimmed %d tool output(s) before chunk", _trimmed)
            except Exception as e:  # noqa: BLE001 — context mgmt must never break the run
                logger.debug("micro-compact failed: %s", e)

        try:
            _chunk_coro = Runner.run(
                agent,
                input=current_input,
                max_turns=chunk_size,
                run_config=run_config,
                hooks=capture_hooks,  # F203.K — capture items in-flight
            )
            if _chunk_timeout_s > 0:
                result = await asyncio.wait_for(_chunk_coro, timeout=_chunk_timeout_s)
            else:
                result = await _chunk_coro
        except asyncio.TimeoutError:
            # The chunk overran its wall budget (hung tool or a stuck agent
            # step). Abort it so the run ALWAYS terminates: advance the turn
            # counter, and after a couple of consecutive timeouts break out.
            _chunk_timeouts += 1
            turns_used += chunk_size
            # Salvage any intel the chunk captured before it hung, so the next
            # chunk doesn't re-explore blind.
            accumulated_facts = _salvage_chunk_intel(capture_hooks, accumulated_facts, tool_history)
            logger.warning(
                "reflective runner: chunk timed out after %.0fs (count=%d) — advancing",
                _chunk_timeout_s,
                _chunk_timeouts,
            )
            if _chunk_timeouts >= _MAX_CHUNK_TIMEOUTS or turns_used >= max_total_turns:
                break
            continue
        except Exception as e:  # noqa: BLE001 — handle MaxTurnsExceeded specially
            # MaxTurnsExceeded inside a chunk = "agent wanted to continue beyond
            # chunk budget". That's expected — the whole point of the reflective
            # runner is to break up long runs into chunks. We should NOT propagate
            # this exception; instead inject reflection + continue next chunk.
            ename = type(e).__name__
            if "MaxTurns" in ename:
                if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                    print(
                        f"\n🪞 [reflective-runner] chunk hit max_turns at total turn {turns_used} — forcing reflection"
                    )
                logger.info(
                    "reflective runner: chunk hit max_turns at total turn %d — injecting reflection and continuing",
                    turns_used,
                )
                # Bump turns_used by chunk_size so we don't loop forever
                turns_used += chunk_size
                if turns_used >= max_total_turns:
                    break
                # Inject a "you ran out of chunk budget" reflection and continue.
                # We don't have a clean result to base history on — fall back to
                # current_input as-is plus reflection nudge.
                if isinstance(current_input, list):
                    base_history = current_input
                else:
                    base_history = [{"role": "user", "content": str(current_input)}]

                # B9 (FASE 2) — even on the MaxTurnsExceeded path the chunk
                # may have produced useful tool outputs (captured by
                # ItemCaptureHooks). Reconstruct the chunk text from
                # capture_hooks and run the SAME extract+plan pipeline so
                # the reflection injects facts + next-action regardless of
                # whether the chunk exited cleanly or hit max_turns.
                try:
                    mt_chunk_text = _chunk_text_from_capture(capture_hooks)
                    if mt_chunk_text:
                        chunk_facts_mt = _extract_facts_from_chunk(mt_chunk_text)
                        accumulated_facts = accumulated_facts.merge(chunk_facts_mt)
                except Exception as ee:  # noqa: BLE001
                    logger.debug("MaxTurns extract path failed: %s", ee)

                # FASE 11.M — drain sub-call log on the MaxTurns path too,
                # so cascade rules see the inner args of any planner
                # directives that fired before the chunk's budget ran
                # out. Without this, MaxTurns chunks would leave the
                # subcalls in the buffer to be picked up on the NEXT
                # chunk's drain — by then the rule abstain check is
                # out-of-sync with what the planner emits.
                try:
                    subcall_args_mt = _drain_planner_subcalls()
                    for sub_args in subcall_args_mt:
                        synthetic_mt = _ToolCallRecord(
                            tool_name="planner_subcall",
                            args_hash=_hash_args(sub_args),
                            args_preview=sub_args[:200],
                        )
                        tool_history.append(synthetic_mt)
                except Exception as ee:  # noqa: BLE001
                    logger.debug("MaxTurns subcall drain failed: %s", ee)

                next_action_mt: NextActionRecommendation | None = None
                try:
                    prior_args_mt = [r.args_preview for r in tool_history]
                    next_action_mt = plan_next_action(
                        accumulated_facts,
                        prior_tool_args=prior_args_mt,
                        intent="",
                    )
                except Exception as ee:  # noqa: BLE001
                    logger.debug("MaxTurns planner path failed: %s", ee)

                if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                    print(
                        f"\n🪞 [reflective-runner] MaxTurns-path intel: "
                        f"facts_empty={accumulated_facts.is_empty()} "
                        f"next_action={'yes' if next_action_mt else 'no'}"
                    )

                facts_block_mt = ""
                if not accumulated_facts.is_empty():
                    facts_block_mt = accumulated_facts.render_for_prompt() + "\n"

                # G4: high-confidence planner output goes ABOVE everything
                # on the MaxTurns path too — same rationale as the normal
                # branch (Pyrat run #10 showed the model ignoring a buried
                # directive). Substitute target placeholder with the first
                # known host so the invocation reads as concrete, not
                # template.
                next_action_top_mt = ""
                next_action_block_mt = ""
                if next_action_mt is not None:
                    target_host_mt = accumulated_facts.hosts[0] if accumulated_facts.hosts else ""
                    rendered_mt = _render_planner(next_action_mt, target_host=target_host_mt) + "\n"
                    if next_action_mt.confidence >= 0.85:
                        next_action_top_mt = rendered_mt
                    else:
                        next_action_block_mt = rendered_mt

                reflection_msg = (
                    f"\n---\n## 🪞 Reflection forced (chunk budget exhausted)\n\n"
                    f"{next_action_top_mt}"
                    f"{facts_block_mt}"
                    f"{next_action_block_mt}"
                    f"Ran out of {chunk_size} turns without a final answer. "
                    f"Pause + decide: (a) emit final summary with what you have, "
                    f"or (b) pick ONE next decisive tool call (no repetition).\n"
                )
                current_input = base_history + [{"role": "user", "content": reflection_msg}]
                continue
            if "StuckError" in ename:
                # The stuck-detector aborted the chunk: the agent is in an
                # irrecoverable loop (identical tool+args+result repeated
                # abort_at times). More chunks won't help — finalize
                # gracefully with whatever was captured in-flight so the
                # caller (kryon investigate) still produces a PARTIAL report
                # instead of dying with no artifact. Converts a "failed, no
                # report" run into a "partial findings" run.
                logger.warning(
                    "reflective runner: stuck-loop abort at turn %d — finalizing with partial findings: %s",
                    turns_used,
                    e,
                )
                if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in (
                    "1",
                    "true",
                    "yes",
                ):
                    print(
                        f"\n🛑 [reflective-runner] stuck-loop abort at turn "
                        f"{turns_used} — finalizing with partial findings"
                    )
                # Salvage facts captured by the hooks before the loop tripped.
                try:
                    stuck_chunk_text = _chunk_text_from_capture(capture_hooks)
                    if stuck_chunk_text:
                        accumulated_facts = accumulated_facts.merge(_extract_facts_from_chunk(stuck_chunk_text))
                except Exception as ee:  # noqa: BLE001
                    logger.debug("stuck-path extract failed: %s", ee)
                from kryon.sdk.agents.run_outcome import classify_run_exception

                # Shared classifier → same wording as the REST route + CLI.
                _outcome = classify_run_exception(e)
                stuck_note = (
                    _outcome.message
                    if _outcome is not None
                    else "⚠️ El agente se detuvo en un loop irrecuperable. "
                    "Los hallazgos abajo son PARCIALES y requieren verificación."
                )
                if last_result is not None:
                    try:
                        prior = getattr(last_result, "final_output", "") or ""
                        last_result.final_output = (  # type: ignore[attr-defined]
                            prior + "\n\n" + stuck_note
                        ).strip()
                    except Exception:  # noqa: BLE001
                        pass
                else:
                    # Stuck in the very first chunk — no clean result yet.
                    # Build a minimal carrier so the final return block can
                    # attach accumulated_items + the captured chain to it.
                    from types import SimpleNamespace

                    last_result = SimpleNamespace(final_output=stuck_note, new_items=[])
                break
            # Transient server-side rejection of a malformed tool_call (local model
            # inlined a large multi-line payload — e.g. an SSH key — producing
            # invalid JSON args; llama.cpp answers HTTP 500 "Failed to parse tool
            # call arguments"). Recoverable: nudge the model off inlining big blobs
            # and retry, instead of killing a run that's one step from a foothold.
            _emsg = str(e).lower()
            _is_tool_json_500 = (
                "internalservererror" in ename.lower()
                or getattr(e, "status_code", None) == 500
                or "parse tool call" in _emsg
                or "failed to parse tool call arguments" in _emsg
            )
            # Fingerprint the failing payload (the "last read:" blob tail). If the
            # model re-emits the SAME malformed tool_call despite the nudge, it's
            # stubborn — bail now instead of burning more full-prompt retries.
            _fp = _emsg.split("last read:", 1)[-1][:80] if "last read:" in _emsg else _emsg[:80]
            _repeated_500 = _is_tool_json_500 and _fp == _last_500_fingerprint
            if _repeated_500:
                logger.warning(
                    "reflective runner: model re-emitted the SAME malformed tool_call "
                    "after a nudge at turn %d — giving up (retrying would just burn tokens)",
                    turns_used,
                )
            if _is_tool_json_500 and not _repeated_500 and _server_errors + 1 < _MAX_SERVER_ERRORS:
                _server_errors += 1
                _last_500_fingerprint = _fp
                turns_used += 1  # count the wasted turn so the run always progresses
                logger.warning(
                    "reflective runner: server rejected a malformed tool_call "
                    "(count=%d) at turn %d — nudging + retrying: %s",
                    _server_errors,
                    turns_used,
                    str(e)[:200],
                )
                # Salvage the chunk's captured intel before retrying — the tools it
                # ran before the 500 are real progress and shouldn't be lost.
                accumulated_facts = _salvage_chunk_intel(capture_hooks, accumulated_facts, tool_history)
                base_history = (
                    current_input
                    if isinstance(current_input, list)
                    else [{"role": "user", "content": str(current_input)}]
                )
                nudge = (
                    "⚠️ Tu último tool_call fue RECHAZADO por el servidor: los "
                    "argumentos no eran JSON válido. Causa: pegaste un blob "
                    "multilínea (la clave SSH) dentro del argumento; los saltos de "
                    "línea y comillas rompen el JSON. REGLA ABSOLUTA: NUNCA tipees "
                    "ni pegues contenido grande/multilínea dentro de un tool_call.\n"
                    "En su lugar, hacé que el COMANDO MISMO produzca el archivo sin "
                    "que vos escribas el contenido. Para la clave SSH que obtuviste "
                    "por SSRF, NO la copies: re-ejecutá el MISMO curl del SSRF y "
                    "redirigí su salida a un archivo, extrayendo la clave con sed en "
                    "UNA sola línea (sin comillas multilínea):\n"
                    "  curl -s -X POST http://beta.creative.thm/ "
                    "-d 'url=<tu_payload_ssrf>' | sed -n '/BEGIN OPENSSH/,/END OPENSSH/p' > /tmp/id_rsa\n"
                    "  chmod 600 /tmp/id_rsa\n"
                    "  ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no <user>@<host> 'id; cat ~/user.txt'\n"
                    "Así la clave jamás pasa por los argumentos del tool_call. "
                    "Mantené cada tool_call chico y con JSON estrictamente válido."
                )
                current_input = base_history + [{"role": "user", "content": nudge}]
                continue
            logger.exception("reflective runner chunk failed at turn %d: %s", turns_used, e)
            raise

        # Count turns consumed (one ModelResponse per turn).
        raw = getattr(result, "raw_responses", None) or []
        consumed = len(raw) if raw else 1  # conservative fallback
        turns_used += consumed
        last_result = result

        # F203.H — accumulate new_items so the final returned result reflects
        # the FULL conversation, not just the last chunk's slice.
        chunk_items = getattr(result, "new_items", []) or []
        accumulated_items.extend(chunk_items)

        # Update tool call history.
        new_records = _extract_tool_calls(chunk_items)
        tool_history.extend(new_records)

        # FASE 11.M — drain the sub-call log populated by
        # ``execute_planner_directive`` and merge those entries into
        # ``tool_history`` as synthetic ``planner_subcall`` records.
        # Without this, ``_was_invoked(prior_args, "common.txt")``
        # checks in planner rules never matched, because the wrapper
        # invocation in tool_history was always ``execute_planner_
        # directive`` — never the inner args of the underlying
        # ``run_command``. Bench Robots (2026-05-26) showed the
        # cascade rule for big.txt failing to fire for this exact
        # reason. The synthetic records are flagged with a stable
        # tool_name so downstream consumers can tell them apart.
        try:
            subcall_args_list = _drain_planner_subcalls()
        except Exception as e:  # noqa: BLE001
            logger.debug("planner sub-call drain failed: %s", e)
            subcall_args_list = []
        for sub_args in subcall_args_list:
            synthetic = _ToolCallRecord(
                tool_name="planner_subcall",
                args_hash=_hash_args(sub_args),
                args_preview=sub_args[:200],
            )
            tool_history.append(synthetic)
            new_records.append(synthetic)
        if subcall_args_list and os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
            print(
                f"\n🔗 [reflective-runner] merged "
                f"{len(subcall_args_list)} planner sub-call(s) into "
                f"tool_history (FASE 11.M)"
            )

        if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
            print(
                f"\n🪞 [reflective-runner] chunk done: turn={turns_used}, "
                f"new_items={len(chunk_items)}, accumulated={len(accumulated_items)}, "
                f"tool_calls_total={len(tool_history)}"
            )

        # Did the agent finish? (final_output set + no pending tool calls)
        if not _has_pending_tool_calls(result):
            # FASE 11.E — before returning, check whether this
            # "finished" answer is actually a premature summary trying
            # to bypass the FASE 11.B reflection-cadence detector. If
            # so AND we haven't exhausted the rejection budget, inject
            # a hard rejection reflection and continue the chunk loop
            # instead of returning. Otherwise (legitimate finish OR
            # budget exhausted) follow the normal return path.
            final_output_text = ""
            try:
                fo = getattr(result, "final_output", None)
                final_output_text = str(fo) if fo else ""
            except Exception:  # noqa: BLE001
                final_output_text = ""

            should_reject_final, reject_msg = (False, "")
            try:
                # FASE 11.N — count REAL tool calls (excluding synthetic
                # planner_subcall records) + pick class-appropriate
                # threshold so recon-class chains (5+ calls expected)
                # don't terminate as early as eval-class chains (3+).
                _real_count_final = _count_real_tool_calls(new_records)
                _threshold_final = _resolve_threshold_for_class(accumulated_facts)
                should_reject_final, reject_msg = _evaluate_final_for_premature(
                    final_output_text,
                    tool_calls_in_chunk=_real_count_final,
                    has_foothold=_has_foothold(accumulated_facts),
                    rejection_count=premature_rejection_count,
                    max_rejections=premature_max_rejections,
                    threshold_tool_calls=_threshold_final,
                )
            except Exception as e:  # noqa: BLE001 — never let the gate crash the run
                logger.debug("FASE 11.E final-output gate failed: %s", e)

            if should_reject_final:
                premature_rejection_count += 1
                logger.warning(
                    "FASE 11.E premature final_output rejected at turn %d (rejection=%d/%d) — forcing reflection turn",
                    turns_used,
                    premature_rejection_count,
                    premature_max_rejections,
                )
                if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                    print(
                        f"\n🛑 [reflective-runner] PREMATURE FINAL REJECTED "
                        f"at turn {turns_used} "
                        f"(rejection {premature_rejection_count}/"
                        f"{premature_max_rejections}) — injecting "
                        f"reflection + continuing"
                    )
                # Re-anchor input on the chunk's conversation history
                # (so the rejection reflection lands on top of whatever
                # the model just emitted) and continue the chunk loop.
                try:
                    base_history = result.to_input_list()
                except Exception:  # noqa: BLE001
                    base_history = [{"role": "user", "content": str(current_input)}]
                current_input = base_history + [{"role": "user", "content": reject_msg}]
                # Do NOT return — continue the while loop so the model
                # gets another chunk to try alternatives.
                continue

            logger.debug("reflective runner: agent finished at turn %d", turns_used)
            # F203.H — patch the accumulated items list onto the returned
            # result so write-back sees all chunks' tool calls.
            try:
                result.new_items = accumulated_items
            except (AttributeError, Exception):  # noqa: BLE001
                pass
            # F203.K — attach captured hooks chain so write-back can use
            # it as fallback when new_items duck-typing fails.
            try:
                result._captured_chain = capture_hooks.to_chain()  # type: ignore[attr-defined]
            except (AttributeError, Exception):  # noqa: BLE001
                pass
            # FASE 6 — clear the planner ContextVar so a leaked state
            # doesn't feed a later run in the same task. Best-effort.
            try:
                _clear_planner_state()
            except Exception:  # noqa: BLE001
                pass
            try:
                _adherence.flush()
            except Exception:  # noqa: BLE001
                pass
            return result

        # Stop if we've consumed the budget.
        if turns_used >= max_total_turns:
            break

        # Inject reflection user message for the next chunk.
        # Only judge "stuck" on chunks that actually called tools. _is_stuck reads
        # the GLOBAL history tail, so a chunk that emits NO tool call (the model
        # narrating / concluding) would otherwise keep matching the stale tail and
        # falsely escalate "repeated X" — when in fact the model stopped looping.
        stuck = _is_stuck(tool_history, threshold=stuck_threshold) if new_records else None
        # Escalate a persistent stuck pattern to a hard stop. _is_stuck only
        # warns via the reflection prompt; a weak agentic model ignores it and
        # re-issues the same tool+args indefinitely (qwen3-8b: ~48× one URL).
        # Counting consecutive stuck chunks and breaking turns that into an
        # abort so the deterministic findings still surface.
        if stuck is not None:
            consecutive_stuck_count += 1
            if consecutive_stuck_count >= _DEFAULT_STUCK_ABORT_TRIGGER:
                logger.warning(
                    "stuck-loop abort at turn %d: tool '%s' repeated identically "
                    "across %d consecutive chunks — breaking the loop",
                    turns_used,
                    stuck.tool_name,
                    consecutive_stuck_count,
                )
                operator_input_summary = (
                    "## 🛑 Investigación abortada — bucle detectado\n\n"
                    f"El agente repitió `{stuck.tool_name}` con argumentos idénticos en "
                    f"{consecutive_stuck_count} chunks consecutivos sin progresar (mismo "
                    "resultado cada vez); se cortó el loop para no malgastar el budget.\n\n"
                    "Revisá los hallazgos deterministas (sección **Verificado**) — el "
                    "modelo local no está razonando sobre los resultados de las tools."
                )
                operator_input_requested = True
                break
        elif new_records:
            # A chunk that called a DIFFERENT tool breaks the loop → reset. A chunk
            # with no tool call holds the counter (handled above) instead of
            # resetting, so alternating "repeat / narrate / repeat" can't evade it.
            consecutive_stuck_count = 0
        last_output = ""
        try:
            fo = getattr(result, "final_output", None)
            last_output = str(fo) if fo else ""
        except Exception:  # noqa: BLE001
            last_output = ""

        # F203.AX — intra-turn degeneracy check. Runs over the FULL chunk
        # text (all ModelResponses concatenated), not just final_output.
        # If detected, the reflection prompt is upgraded to a hard
        # "STOP REPEATING" directive. Independent of stuck-pattern
        # (which only fires across tool_calls).
        degen_pattern: str | None = None
        chunk_text = ""
        try:
            chunk_text = _extract_chunk_text(result)
            degen_pattern = _detect_intra_turn_degeneracy(chunk_text)
        except Exception as e:  # noqa: BLE001
            logger.debug("intra-turn degeneracy probe failed: %s", e)

        # FASE 1 (G1+G2) — extract structured facts from this chunk and merge into
        # the cross-chunk accumulator. CRITICAL: the per-tool parsers need the RAW
        # tool output (nmap/ldapsearch/GetNPUsers), which lives in the capture hooks
        # — NOT in `chunk_text`. `_extract_chunk_text(result)` only ever yields the
        # model's `final_output` (ModelResponse has no `.message`/`.content`), so on
        # the happy path the fact extractor used to see only the model's polished
        # prose and the whole intel pipeline ran near-empty. Feed it the captured
        # raw tool outputs (▸-marked, the same source the unhappy paths use), plus
        # the model text for the generic hint/hash pass.
        try:
            capture_text = _chunk_text_from_capture(capture_hooks)
            fact_source = (capture_text + "\n" + chunk_text).strip() or chunk_text
            chunk_facts = _extract_facts_from_chunk(fact_source)
            accumulated_facts = accumulated_facts.merge(chunk_facts)
        except Exception as e:  # noqa: BLE001
            logger.debug("fact extraction probe failed: %s", e)

        if not accumulated_facts.is_empty() and os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in (
            "1",
            "true",
            "yes",
        ):
            print(
                f"\n📊 [reflective-runner] facts at turn {turns_used}: "
                f"users={len(accumulated_facts.users)} "
                f"shares={len(accumulated_facts.shares)} "
                f"hashes={len(accumulated_facts.hashes)} "
                f"domains={len(accumulated_facts.domains)} "
                f"creds={len(accumulated_facts.creds)} "
                f"hints={len(accumulated_facts.hints)}"
            )

        # FASE 11.B — premature-summary detector. Operates on this
        # chunk's text + this chunk's tool-call count + cross-chunk
        # foothold evidence. Surfaces an imperative reflection block
        # demanding 3 hypotheses + a concrete probe instead of letting
        # the model exit on a half-baked "Resumen Ejecutivo".
        premature_summary_detected = False
        try:
            # FASE 11.N — real count (no planner_subcall) + class
            # threshold so recon-class targets aren't flagged premature
            # at 3 calls (the eval-class floor).
            tool_calls_in_chunk = _count_real_tool_calls(new_records)
            chunk_has_foothold = _has_foothold(accumulated_facts)
            threshold_tool_calls_for_chunk = _resolve_threshold_for_class(
                accumulated_facts,
            )
            premature_summary_detected = _detect_premature_summary(
                chunk_text,
                tool_calls_in_chunk=tool_calls_in_chunk,
                has_foothold=chunk_has_foothold,
                threshold_tool_calls=threshold_tool_calls_for_chunk,
            )
        except Exception as e:  # noqa: BLE001 — never break the chunk on a probe
            logger.debug("premature-summary detector failed: %s", e)

        if premature_summary_detected:
            logger.warning(
                "FASE 11.B premature summary detected at turn %d (tool_calls_in_chunk=%d, has_foothold=%s)",
                turns_used,
                len(new_records),
                _has_foothold(accumulated_facts),
            )
            if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                print(
                    f"\n🛑 [reflective-runner] PREMATURE SUMMARY at turn "
                    f"{turns_used} — model emitted summary marker after "
                    f"{len(new_records)} tool calls without foothold"
                )

        # FASE 2 (G3) — run the planner over (facts, tool_history) and
        # let it emit a concrete next-action recommendation. The rules
        # are conservative (each abstains without enough signal), so a
        # ``None`` here is the common case in early chunks — the
        # reflection prompt simply doesn't include the recommendation
        # block when there's nothing solid to recommend.
        next_action: NextActionRecommendation | None = None
        prior_args = [r.args_preview for r in tool_history]
        try:
            next_action = plan_next_action(
                accumulated_facts,
                prior_tool_args=prior_args,
                intent="",
            )
        except Exception as e:  # noqa: BLE001 — planner failure must not break the chunk
            logger.debug("exploit_chain_planner probe failed: %s", e)

        # FASE 6 — refresh the runtime ContextVar so the
        # ``execute_planner_directive`` function_tool can re-run the
        # planner against the same state without re-parsing the chat
        # history. The tool reads this in the NEXT chunk's tool-use
        # loop; updating here means each chunk's directives reflect
        # the freshest facts and history.
        try:
            _set_planner_state(accumulated_facts, prior_args)
        except Exception as e:  # noqa: BLE001 — best-effort, never bubble
            logger.debug("planner runtime state set failed: %s", e)

        if next_action is not None and os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
            print(
                f"\n🎯 [reflective-runner] next_action at turn {turns_used}: "
                f"{next_action.tool}({next_action.args[:80]}...) "
                f"confidence={next_action.confidence:.2f}"
            )

        # Tier-2 telemetry — resolve the PREVIOUS injection against the tool the model
        # actually issued since then (first real tool_history entry after the injection),
        # then record this chunk's high-confidence injection. Fully guarded: telemetry
        # must never break the chunk.
        try:
            new_calls = [r for r in tool_history[_adh_th_len:] if r.tool_name != "planner_subcall"]
            if new_calls:
                _adherence.record_action(tool=new_calls[0].tool_name)
            if next_action is not None and next_action.confidence >= 0.92:
                _adherence.record_injection(
                    turn=turns_used, tool=next_action.tool, confidence=next_action.confidence
                )
                _adh_th_len = len(tool_history)
        except Exception as e:  # noqa: BLE001 — telemetry is best-effort
            logger.debug("adherence telemetry skipped: %s", e)

        # Tier 1.1 — deterministic execution of a high-confidence directive instead of
        # injecting "please run this" and hoping. Double-gated (KRYON_PLANNER_AUTOEXEC AND
        # red-team profile) so it's OFF for banking/passive runs. We run the directive via
        # the SAME path as execute_planner_directive and inject its OUTPUT next turn, so the
        # model narrates the result rather than deciding whether to obey (the gap FASE 11.J
        # tried to close with ever-harder prompt wording).
        _autoexec_block = ""
        if next_action is not None and next_action.confidence >= 0.92 and _planner_autoexec_enabled():
            try:
                from kryon.tools.intelligence.planner_executor import (  # noqa: PLC0415
                    execute_planner_directive,
                )

                out = await execute_planner_directive._raw_fn(target_host="")
                if out and "[NO DIRECTIVE]" not in out:
                    _autoexec_block = (
                        "\n\n# PLANNER AUTO-EXECUTED (deterministic — do NOT re-run this; "
                        "build on the result below):\n" + str(out)[:4000] + "\n"
                    )
                    _adherence.record_action(tool="execute_planner_directive")  # forced adherence
                    if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                        print(f"\n⚙️  [reflective-runner] auto-executed directive {next_action.tool} at turn {turns_used}")
            except Exception as e:  # noqa: BLE001 — autoexec failure must not break the chunk
                logger.debug("planner autoexec skipped: %s", e)

        # G7 (FASE 4) — update stall window AFTER the planner has
        # produced (or not produced) this chunk's recommendation. The
        # check fires only when the deque is full of identical entries
        # AND the facts signature hasn't moved since the window opened.
        rec_sig = _recommendation_signature(next_action)
        recent_recs_window.append(rec_sig)
        current_facts_sig = _facts_signature(accumulated_facts)
        if len(recent_recs_window) == 1:
            # First entry — snapshot the facts signature so future
            # stall checks can compare against it.
            prev_facts_sig_for_stall = current_facts_sig
        stall_detected = _is_stall(
            recent_recs_window,
            prev_facts_sig_for_stall,
            current_facts_sig,
        )
        if stall_detected:
            logger.warning(
                "G7 stall detected at turn %d: same recommendation %d turns + no facts change",
                turns_used,
                _DEFAULT_STALL_THRESHOLD,
            )
            consecutive_stall_count += 1
            if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                print(
                    f"\n🛑 [reflective-runner] STALL DETECTED at turn "
                    f"{turns_used} — recommendation repeated "
                    f"{_DEFAULT_STALL_THRESHOLD}x, facts sig stuck at "
                    f"{prev_facts_sig_for_stall!r} "
                    f"(consecutive_stalls={consecutive_stall_count}/"
                    f"{_DEFAULT_OPERATOR_PAIR_STALL_TRIGGER})"
                )
            # FASE 8.B — when consecutive stalls cross the operator-
            # pair trigger, the autonomous loop genuinely can't make
            # progress. Build a REQUEST_OPERATOR_INPUT summary and
            # break the loop. The summary becomes the run's final
            # answer (replacing whatever the agent was going to emit).
            if consecutive_stall_count >= _DEFAULT_OPERATOR_PAIR_STALL_TRIGGER:
                logger.warning(
                    "FASE 8.B operator-pair fallback firing at turn %d "
                    "after %d consecutive stalls — emitting "
                    "REQUEST_OPERATOR_INPUT and breaking the loop",
                    turns_used,
                    consecutive_stall_count,
                )
                if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                    print(
                        f"\n🚨 [reflective-runner] OPERATOR-PAIR FALLBACK at turn {turns_used} — REQUEST_OPERATOR_INPUT"
                    )
                try:
                    operator_input_summary = _build_operator_input_request(
                        accumulated_facts,
                        next_action,
                        tool_history,
                        turns_used,
                    )
                except Exception as e:  # noqa: BLE001
                    logger.debug("operator-pair summary build failed: %s", e)
                    operator_input_summary = (
                        "REQUEST_OPERATOR_INPUT — agent stuck. Inspect ExtractedFacts + history manually."
                    )
                operator_input_requested = True
                break
            # After firing once (but below the operator trigger), reset
            # the window so we don't spam the warning every subsequent
            # chunk while the consecutive-stall counter accrues.
            recent_recs_window.clear()
            prev_facts_sig_for_stall = current_facts_sig
        elif current_facts_sig != prev_facts_sig_for_stall:
            # Facts moved → window is no longer interesting for stall
            # purposes. Reset baseline so a future repeat starts fresh.
            # Also reset the consecutive-stall counter: progress
            # means the operator-pair trigger should start over.
            prev_facts_sig_for_stall = current_facts_sig
            consecutive_stall_count = 0

        if degen_pattern:
            logger.warning(
                "F203.AX intra-turn degeneracy detected at turn %d: %r",
                turns_used,
                degen_pattern[:120],
            )
            if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                print(
                    f"\n🚨 [reflective-runner] INTRA-TURN DEGENERACY at turn "
                    f"{turns_used}: pattern={degen_pattern[:80]!r}"
                )

        reflection_msg = _build_reflection_prompt(
            turns_used=turns_used,
            total_turns_cap=max_total_turns,
            tool_history=tool_history,
            last_output_summary=last_output,
            stuck_record=stuck,
            degen_pattern=degen_pattern,
            extracted_facts=accumulated_facts,
            next_action=next_action,
            stall_detected=stall_detected,
            premature_summary_detected=premature_summary_detected,
        )
        # Tier 1.1 — if we auto-executed the directive this chunk, hand the model the OUTPUT
        # (authoritative, like a pre_hook) instead of a "please run it" directive.
        if _autoexec_block:
            reflection_msg = reflection_msg + _autoexec_block

        if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
            print(
                f"\n🪞 [reflective-runner] injecting reflection turn (turn {turns_used}/"
                f"{max_total_turns}, stuck={stuck.tool_name if stuck else 'no'})"
            )

        try:
            base_history = result.to_input_list()
        except Exception:  # noqa: BLE001
            # Fallback: re-use the original input as a string concatenation.
            base_history = [{"role": "user", "content": str(current_input)}]

        current_input = base_history + [{"role": "user", "content": reflection_msg}]

    # If NO chunk ever returned a clean result (run ended on the wall budget, or
    # every chunk hit MaxTurns mid-flight), last_result is None — but the agent
    # may well have run tools (captured by the hooks). Build a minimal carrier so
    # the report reflects that activity instead of "Tool calls: 0". Same shape as
    # the StuckError finalize path; final_output stays "" (the agent genuinely
    # didn't produce a final summary).
    if last_result is None:
        _captured_final = capture_hooks.to_chain()
        if _captured_final or accumulated_items:
            from types import SimpleNamespace

            last_result = SimpleNamespace(final_output="", new_items=accumulated_items)

    # F203.H — final return: patch accumulated_items onto last_result so
    # downstream consumers see the full history even when exiting via the
    # max_total_turns budget (not just early-finish path).
    # F203.K — also attach captured chain from hooks (covers items lost
    # to MaxTurnsExceeded chunks).
    if last_result is not None:
        try:
            last_result.new_items = accumulated_items
        except (AttributeError, Exception):  # noqa: BLE001
            pass
        try:
            last_result._captured_chain = capture_hooks.to_chain()  # type: ignore[attr-defined]
        except (AttributeError, Exception):  # noqa: BLE001
            pass
        # FASE 8.B — when the operator-pair fallback fired we replace
        # the run's final_output with the structured REQUEST_OPERATOR_
        # INPUT summary so downstream (kryon investigate's final
        # reporter) surfaces it instead of whatever partial state the
        # agent left behind. The summary is markdown ready for the
        # REPL to render.
        if operator_input_requested:
            try:
                last_result.final_output = operator_input_summary  # type: ignore[attr-defined]
                last_result._operator_input_requested = True  # type: ignore[attr-defined]
            except (AttributeError, Exception):  # noqa: BLE001
                pass
    # FASE 6 — release the planner ContextVar on the
    # max-total-turns exit path too. Mirrors the early-return branch.
    try:
        _clear_planner_state()
    except Exception:  # noqa: BLE001
        pass
    try:
        _adherence.flush()
    except Exception:  # noqa: BLE001
        pass
    return last_result


__all__ = [
    "run_with_reflection",
    "_build_reflection_prompt",
    "_extract_tool_calls",
    "_is_stuck",
    "_hash_args",
    "_ToolCallRecord",
    "_detect_intra_turn_degeneracy",
    "_extract_chunk_text",
    "_chunk_text_from_capture",
    "_extract_facts_from_chunk",
    "_facts_signature",
    "_recommendation_signature",
    "_is_stall",
    "_build_operator_input_request",
    "_detect_premature_summary",
    "_has_foothold",
    "_evaluate_final_for_premature",
    "_count_real_tool_calls",
    "_resolve_threshold_for_class",
]
