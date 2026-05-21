"""F203.F — Memory write-through al learning loop post-investigate.

Después de un `kryon investigate`, captura la experiencia (tools usadas,
findings, outcome, summary) y la persiste vía `learning.experiences.add_experience`.
Esto permite que futuros investigates puedan `recall_similar_experiences`
sin que el operador tenga que invocar `/experiences close` manualmente.

A diferencia de `services/auto_extract.py` (que asume REPL message history
y depende del chain_extractor), esta función trabaja directo sobre el
`RunResult` del SDK.

Banca-safe:
- Solo escribe a `~/.kryon/.../experiences.chromadb` (storage local del
  learning loop), no toca network ni filesystem fuera de ese path.
- Si el experience NO tiene chain >= 2 tool calls, se descarta — no
  saturamos la base con runs triviales.
- Failures (ChromaDB ausente, embedder offline, etc) son non-fatal:
  el investigate retorna OK pero sin write-through.

KRYON_NO_WRITEBACK=1 desactiva el write-through global.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# Outcome heuristics on final_output text. Order matters — first match wins.
_FAIL_MARKERS = (
    "no se pudo",
    "no logré",
    "no pude",
    "sin signal",
    "no encontré",
    "did not find",
    "could not",
    "no results",
)
_PARTIAL_MARKERS = (
    "parcial",
    "indicio",
    "sospechoso",
    "podría ser",
    "tentative",
    "needs verification",
    "necesita verificación",
    "no concluyente",
)


def _outcome_from_summary(text: str) -> str:
    """Cheap heuristic: classify final_output into success/partial/fail.

    Used for the learning loop's outcome rank. The synthesizer rejects
    drafts with outcome=fail, so this gate matters.
    """
    if not text:
        return "fail"
    lower = text.lower()
    for marker in _FAIL_MARKERS:
        if marker in lower:
            return "fail"
    for marker in _PARTIAL_MARKERS:
        if marker in lower:
            return "partial"
    # Default: assume success when the agent emitted a final summary
    # without obvious failure language. The synthesizer's other quality
    # gates (chain_len, profile signal) catch low-value runs.
    return "success"


def _extract_chain(new_items: list[Any]) -> list[dict[str, Any]]:
    """Pull tool calls + outputs from RunResult.new_items.

    Returns a list shaped to match the synthesizer's expected chain
    schema: [{"tool": name, "args": ..., "output_preview": "..."}].

    Duck-typed to handle real SDK item shapes:
    - ToolCallItem: item.type == "tool_call_item", raw_item is
      ResponseFunctionToolCall with .name/.arguments/.call_id.
    - ToolCallOutputItem: item.type == "tool_call_output_item",
      raw_item is dict {"call_id": ..., "output": ..., "type": ...}
      AND item.output exposes the wrapper output too.
    - MessageOutputItem: type == "message_output_item" — skip.
    """
    def _g(obj: Any, key: str, default: Any = None) -> Any:
        """Get attr OR dict key, since SDK mixes both."""
        if obj is None:
            return default
        v = getattr(obj, key, None)
        if v is not None:
            return v
        if isinstance(obj, dict):
            return obj.get(key, default)
        return default

    chain: list[dict[str, Any]] = []
    # Map tool_call_id -> chain index for output attachment
    call_id_to_idx: dict[str, int] = {}

    for item in new_items:
        # F203.H — check the item.type marker first (more reliable than
        # duck-typing raw_item attrs).
        item_type = getattr(item, "type", "") or ""
        raw = getattr(item, "raw_item", None)

        # --- Tool call branch ---
        if item_type == "tool_call_item" or _g(raw, "name"):
            tool_name = (
                _g(raw, "name")
                or _g(raw, "tool_name")
                or "unknown_tool"
            )
            args = _g(raw, "arguments") or _g(raw, "args") or {}
            call_id = _g(raw, "call_id") or _g(raw, "id") or ""
            entry = {
                "tool": str(tool_name),
                "args": str(args)[:500],
                "output_preview": "",
            }
            chain.append(entry)
            if call_id:
                call_id_to_idx[str(call_id)] = len(chain) - 1
            continue

        # --- Tool output branch ---
        if item_type == "tool_call_output_item" or _g(raw, "output") is not None:
            # Output may be on the wrapper (item.output) OR on raw_item.
            output = (
                getattr(item, "output", None)
                or _g(raw, "output")
                or _g(raw, "content")
            )
            call_id = _g(raw, "call_id") or _g(raw, "tool_call_id")
            if output is not None:
                idx = None
                if call_id:
                    idx = call_id_to_idx.get(str(call_id))
                if idx is None and chain:
                    for i in range(len(chain) - 1, -1, -1):
                        if not chain[i]["output_preview"]:
                            idx = i
                            break
                if idx is not None:
                    chain[idx]["output_preview"] = str(output)[:500]
            continue

        # MessageOutputItem / other → skip (no tool data).

    return chain


def _build_profile_from_hints(hints: dict[str, Any]) -> dict[str, Any]:
    """Compose target_profile from intent classification hints."""
    profile: dict[str, Any] = {
        "tech": [],
        "ports": [],
        "host": "",
    }
    urls = hints.get("urls") or []
    if urls:
        # Use first URL hostname as host
        from urllib.parse import urlparse
        try:
            parsed = urlparse(urls[0])
            profile["host"] = parsed.netloc or ""
            if parsed.scheme == "https":
                profile["ports"].append(443)
            elif parsed.scheme == "http":
                profile["ports"].append(80)
        except Exception:  # noqa: BLE001
            pass
    # Pull tech hints from keywords (heuristic)
    keywords = hints.get("keywords") or []
    tech_keywords = {
        "moodle", "wordpress", "tomcat", "nginx", "apache",
        "java", "php", "python", "nodejs", "react", "vue",
        "mysql", "postgresql", "mongo", "redis",
    }
    for kw in keywords:
        if kw in tech_keywords:
            profile["tech"].append(kw)
    return profile


def write_back_from_investigate(
    prompt: str,
    hints: dict[str, Any],
    result: Any,
    *,
    auto_synth: bool = True,
) -> str | None:
    """Persist an investigation as a learning loop experience.

    Args:
        prompt: The original user prompt to `kryon investigate`.
        hints: Output of `_classify_intent` (mode, urls, keywords, etc).
        result: The RunResult returned by Runner / run_with_reflection.
        auto_synth: If True, attempt skill draft synthesis after persist
                    (F1 pipeline). Failures are non-fatal.

    Returns:
        The experience id on success, or None when skipped (KRYON_NO_WRITEBACK,
        empty chain, ChromaDB unavailable, etc).
    """
    if os.environ.get("KRYON_NO_WRITEBACK", "").lower() in ("1", "true", "yes"):
        logger.info("write-back skipped: KRYON_NO_WRITEBACK set")
        return None

    new_items = getattr(result, "new_items", None) or []
    chain = _extract_chain(new_items)

    # F203.K — fallback to captured chain from RunHooks when result.new_items
    # extraction yields too few items (typical when chunks hit MaxTurnsExceeded
    # and the SDK dropped them). The hooks captured items in-flight, so they
    # survive even when result objects are lost.
    captured_chain = getattr(result, "_captured_chain", None)
    if isinstance(captured_chain, list) and len(captured_chain) > len(chain):
        logger.info(
            "write-back: using hooks-captured chain (%d items) over result.new_items (%d items)",
            len(captured_chain), len(chain),
        )
        chain = captured_chain

    # F203.H — KRYON_WRITEBACK_DEBUG=1 enables verbose dump of item shapes
    # and extracted chain for debugging SDK item structure changes.
    if os.environ.get("KRYON_WRITEBACK_DEBUG", "").lower() in ("1", "true", "yes"):
        logger.warning("WB-DEBUG: new_items count: %d", len(new_items))
        for i, item in enumerate(new_items[:10]):
            item_attr_type = getattr(item, "type", "?")
            raw_cls = type(getattr(item, "raw_item", None)).__name__
            logger.warning(
                "WB-DEBUG: item[%d] type=%s raw_cls=%s name=%s",
                i, item_attr_type, raw_cls,
                getattr(getattr(item, "raw_item", None), "name", None),
            )
        logger.warning("WB-DEBUG: extracted chain: %d tool calls (captured=%s)",
                       len(chain),
                       len(captured_chain) if isinstance(captured_chain, list) else "n/a")

    if len(chain) < 2:
        logger.info("write-back skipped: chain too short (%d tool calls)", len(chain))
        return None

    final_output = getattr(result, "final_output", None) or ""
    outcome = _outcome_from_summary(str(final_output))

    profile = _build_profile_from_hints(hints)

    experience = {
        "summary": (str(final_output)[:500] if final_output else prompt[:200]),
        "target_profile": profile,
        "chain": chain,
        "outcome": outcome,
        "source": "investigate",
        "original_prompt": prompt[:500],
        "mode": hints.get("mode", "general"),
    }

    try:
        from kryon.learning.experiences import add_experience
    except Exception as e:  # noqa: BLE001
        logger.info("write-back skipped: learning module unavailable: %s", e)
        return None

    try:
        exp_id = add_experience(experience)
    except Exception as e:  # noqa: BLE001
        logger.warning("write-back persistence failed: %s", e)
        return None

    logger.info("investigate write-back: experience %s persisted (outcome=%s, chain=%d)",
                exp_id, outcome, len(chain))

    if auto_synth and outcome in ("success", "partial"):
        try:
            from kryon.learning.draft_writer import try_synthesize_and_persist
            draft_path = try_synthesize_and_persist(experience)
            if draft_path is not None:
                logger.info("auto-synth draft persisted: %s", draft_path)
        except Exception as e:  # noqa: BLE001
            logger.debug("auto-synth skipped: %s", e)

    return exp_id


__all__ = [
    "write_back_from_investigate",
    "_outcome_from_summary",
    "_extract_chain",
    "_build_profile_from_hints",
]
