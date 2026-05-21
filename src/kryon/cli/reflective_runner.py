"""F203.C — Reflective Runner: autocrítica forzada cada N turns.

Wrapper sobre `Runner.run` que entre chunks de N turns inyecta una
"reflection turn" — un user message que fuerza al agent a auto-criticar:

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
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# Default reflection cadence — every 4 turns (~3-4 tool calls).
_DEFAULT_REFLECT_EVERY = 4
# Stuck threshold: 2 identical (tool_name, args_hash) consecutive triggers warning.
_DEFAULT_STUCK_THRESHOLD = 2


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

    return (
        f"\n---\n## 🪞 Reflection turn (turn {turns_used}/{total_turns_cap})\n\n"
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

    while turns_used < max_total_turns:
        chunk_size = min(reflect_every, max_total_turns - turns_used)
        if chunk_size <= 0:
            break

        try:
            result = await Runner.run(
                agent,
                input=current_input,
                max_turns=chunk_size,
                run_config=run_config,
            )
        except Exception as e:  # noqa: BLE001 — handle MaxTurnsExceeded specially
            # MaxTurnsExceeded inside a chunk = "agent wanted to continue beyond
            # chunk budget". That's expected — the whole point of the reflective
            # runner is to break up long runs into chunks. We should NOT propagate
            # this exception; instead inject reflection + continue next chunk.
            ename = type(e).__name__
            if "MaxTurns" in ename:
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
                reflection_msg = (
                    f"\n---\n## 🪞 Reflection forced (chunk budget exhausted)\n\n"
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

        # Update tool call history.
        new_records = _extract_tool_calls(getattr(result, "new_items", []) or [])
        tool_history.extend(new_records)

        # Did the agent finish? (final_output set + no pending tool calls)
        if not _has_pending_tool_calls(result):
            logger.debug("reflective runner: agent finished at turn %d", turns_used)
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

        reflection_msg = _build_reflection_prompt(
            turns_used=turns_used,
            total_turns_cap=max_total_turns,
            tool_history=tool_history,
            last_output_summary=last_output,
            stuck_record=stuck,
        )

        try:
            base_history = result.to_input_list()
        except Exception:  # noqa: BLE001
            # Fallback: re-use the original input as a string concatenation.
            base_history = [{"role": "user", "content": str(current_input)}]

        current_input = base_history + [
            {"role": "user", "content": reflection_msg}
        ]

    return last_result


__all__ = [
    "run_with_reflection",
    "_build_reflection_prompt",
    "_extract_tool_calls",
    "_is_stuck",
    "_hash_args",
    "_ToolCallRecord",
]
