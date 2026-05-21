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

    Duck-typed: tolerant to multiple SDK item shapes.
    """
    chain: list[dict[str, Any]] = []
    # Map tool_call_id -> chain index for output attachment
    call_id_to_idx: dict[str, int] = {}

    for item in new_items:
        raw = getattr(item, "raw_item", None) or item

        # Tool call: has name + arguments
        tool_name = None
        if hasattr(raw, "name") and getattr(raw, "name", None):
            tool_name = str(raw.name)
        elif hasattr(raw, "tool_name") and getattr(raw, "tool_name", None):
            tool_name = str(raw.tool_name)

        if tool_name:
            args = (
                getattr(raw, "arguments", None)
                or getattr(raw, "args", None)
                or {}
            )
            call_id = getattr(raw, "call_id", None) or getattr(raw, "id", None) or ""
            entry = {
                "tool": tool_name,
                "args": str(args)[:500],
                "output_preview": "",
            }
            chain.append(entry)
            if call_id:
                call_id_to_idx[str(call_id)] = len(chain) - 1
            continue

        # Tool output: attach to most-recent call
        output = getattr(raw, "output", None) or getattr(raw, "content", None)
        if output is not None:
            call_id = getattr(raw, "call_id", None) or getattr(raw, "tool_call_id", None)
            idx = None
            if call_id:
                idx = call_id_to_idx.get(str(call_id))
            if idx is None and chain:
                # Fallback: last call without output yet
                for i in range(len(chain) - 1, -1, -1):
                    if not chain[i]["output_preview"]:
                        idx = i
                        break
            if idx is not None:
                chain[idx]["output_preview"] = str(output)[:500]

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
