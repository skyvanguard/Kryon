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
    set_current_state as _set_planner_state,
)
from kryon.intelligence.tool_templates import (
    format_templates_for_recent_tools,
)

logger = logging.getLogger(__name__)


# Default reflection cadence — every 4 turns (~3-4 tool calls).
_DEFAULT_REFLECT_EVERY = 4
# Stuck threshold: 2 identical (tool_name, args_hash) consecutive triggers warning.
_DEFAULT_STUCK_THRESHOLD = 2
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


def _facts_signature(facts: Any) -> str:
    """Compact signature of an ExtractedFacts snapshot used by the
    stall detector to tell "facts moved" from "no progress". Counts
    high-value fields only — turn-by-turn version/hint changes are
    not enough to claim progress on their own."""
    if facts is None:
        return ""
    return (
        f"u={len(getattr(facts, 'users', ()))}"
        f"_h={len(getattr(facts, 'hashes', ()))}"
        f"_c={len(getattr(facts, 'creds', ()))}"
        f"_s={len(getattr(facts, 'shares', ()))}"
        f"_d={len(getattr(facts, 'domains', ()))}"
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

    return (
        f"\n---\n## 🪞 Reflection turn (turn {turns_used}/{total_turns_cap})\n\n"
        f"{next_action_top}"
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
    ngrams = [
        " ".join(words[i : i + ngram_size])
        for i in range(len(words) - ngram_size + 1)
    ]
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
        if content is None:
            continue
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

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: Any
    ) -> None:
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

    while turns_used < max_total_turns:
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

        try:
            result = await Runner.run(
                agent,
                input=current_input,
                max_turns=chunk_size,
                run_config=run_config,
                hooks=capture_hooks,  # F203.K — capture items in-flight
            )
        except Exception as e:  # noqa: BLE001 — handle MaxTurnsExceeded specially
            # MaxTurnsExceeded inside a chunk = "agent wanted to continue beyond
            # chunk budget". That's expected — the whole point of the reflective
            # runner is to break up long runs into chunks. We should NOT propagate
            # this exception; instead inject reflection + continue next chunk.
            ename = type(e).__name__
            if "MaxTurns" in ename:
                if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
                    print(f"\n🪞 [reflective-runner] chunk hit max_turns at total turn {turns_used} — forcing reflection")
                logger.info(
                    "reflective runner: chunk hit max_turns at total turn %d — "
                    "injecting reflection and continuing", turns_used,
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

                if os.environ.get(
                    "KRYON_REFLECT_DEBUG", ""
                ).lower() in ("1", "true", "yes"):
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
                    target_host_mt = (
                        accumulated_facts.hosts[0]
                        if accumulated_facts.hosts
                        else ""
                    )
                    rendered_mt = (
                        _render_planner(next_action_mt, target_host=target_host_mt)
                        + "\n"
                    )
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
                current_input = base_history + [
                    {"role": "user", "content": reflection_msg}
                ]
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

        if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
            print(f"\n🪞 [reflective-runner] chunk done: turn={turns_used}, "
                  f"new_items={len(chunk_items)}, accumulated={len(accumulated_items)}, "
                  f"tool_calls_total={len(tool_history)}")

        # Did the agent finish? (final_output set + no pending tool calls)
        if not _has_pending_tool_calls(result):
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
            return result

        # Stop if we've consumed the budget.
        if turns_used >= max_total_turns:
            break

        # Inject reflection user message for the next chunk.
        stuck = _is_stuck(tool_history, threshold=stuck_threshold)
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

        # FASE 1 (G1+G2) — extract structured facts from this chunk and
        # merge into the cross-chunk accumulator. The render of this
        # accumulator gets injected into the reflection prompt below so
        # the model always sees "what we know" in structured form rather
        # than having to reconstruct it from a truncated transcript.
        try:
            chunk_facts = _extract_facts_from_chunk(chunk_text)
            accumulated_facts = accumulated_facts.merge(chunk_facts)
        except Exception as e:  # noqa: BLE001
            logger.debug("fact extraction probe failed: %s", e)

        if (
            not accumulated_facts.is_empty()
            and os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes")
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

        if next_action is not None and os.environ.get(
            "KRYON_REFLECT_DEBUG", ""
        ).lower() in ("1", "true", "yes"):
            print(
                f"\n🎯 [reflective-runner] next_action at turn {turns_used}: "
                f"{next_action.tool}({next_action.args[:80]}...) "
                f"confidence={next_action.confidence:.2f}"
            )

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
                "G7 stall detected at turn %d: same recommendation %d "
                "turns + no facts change", turns_used, _DEFAULT_STALL_THRESHOLD,
            )
            if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in (
                "1", "true", "yes"
            ):
                print(
                    f"\n🛑 [reflective-runner] STALL DETECTED at turn "
                    f"{turns_used} — recommendation repeated "
                    f"{_DEFAULT_STALL_THRESHOLD}x, facts sig stuck at "
                    f"{prev_facts_sig_for_stall!r}"
                )
            # After firing once, reset the window so we don't spam the
            # warning every subsequent chunk while the operator decides.
            recent_recs_window.clear()
            prev_facts_sig_for_stall = current_facts_sig
        elif current_facts_sig != prev_facts_sig_for_stall:
            # Facts moved → window is no longer interesting for stall
            # purposes. Reset baseline so a future repeat starts fresh.
            prev_facts_sig_for_stall = current_facts_sig

        if degen_pattern:
            logger.warning(
                "F203.AX intra-turn degeneracy detected at turn %d: %r",
                turns_used,
                degen_pattern[:120],
            )
            if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in (
                "1", "true", "yes"
            ):
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
        )

        if os.environ.get("KRYON_REFLECT_DEBUG", "").lower() in ("1", "true", "yes"):
            print(f"\n🪞 [reflective-runner] injecting reflection turn (turn {turns_used}/"
                  f"{max_total_turns}, stuck={stuck.tool_name if stuck else 'no'})")

        try:
            base_history = result.to_input_list()
        except Exception:  # noqa: BLE001
            # Fallback: re-use the original input as a string concatenation.
            base_history = [{"role": "user", "content": str(current_input)}]

        current_input = base_history + [
            {"role": "user", "content": reflection_msg}
        ]

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
    # FASE 6 — release the planner ContextVar on the
    # max-total-turns exit path too. Mirrors the early-return branch.
    try:
        _clear_planner_state()
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
]
