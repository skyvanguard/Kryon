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
# T4-M9: definitive proof-of-success markers win BEFORE the fail markers. Substring
# fail-matching alone misclassified successful runs whose summary merely mentioned a
# negative phrase in passing ("found no results for XSS but got a shell", "this could
# not have been easier — root obtained") → the synthesizer then rejected the draft and
# the learning loop produced 0 drafts. Hard evidence of a foothold overrides that.
_SUCCESS_MARKERS = (
    "uid=0",
    "root@",
    "got root",
    "root obtained",
    "got a shell",
    "shell obtained",
    "reverse shell",
    "foothold",
    "flag{",
    "htb{",
    "thm{",
    "picoctf{",
    "root flag",
    "user flag",
    "credentials cracked",
    "password cracked",
    "compromised",
    "rce confirmed",
    "exploit successful",
    "pwned",
)
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
    # Definitive foothold evidence overrides incidental negative phrasing.
    for marker in _SUCCESS_MARKERS:
        if marker in lower:
            return "success"
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
            tool_name = _g(raw, "name") or _g(raw, "tool_name") or "unknown_tool"
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
            output = getattr(item, "output", None) or _g(raw, "output") or _g(raw, "content")
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


def chain_from_result(result: Any) -> list[dict[str, Any]]:
    """Best tool-call chain available from a run result.

    F203.K — extract from ``result.new_items`` first, then fall back to the
    RunHooks-captured chain (``result._captured_chain``) when the SDK dropped
    items (chunks that hit MaxTurnsExceeded, or a stuck/crashed run that never
    produced a clean result). The hooks fire on every tool invocation, so they
    preserve the real history even when ``new_items`` is empty.

    Shared by the learning write-back AND the investigate report so both agree
    on what the agent actually ran — otherwise the report could claim
    "Tool calls: 0" while the agent did real recon.
    """
    new_items = getattr(result, "new_items", None) or []
    chain = _extract_chain(new_items)
    captured = getattr(result, "_captured_chain", None)
    if isinstance(captured, list) and len(captured) > len(chain):
        logger.info(
            "chain_from_result: using hooks-captured chain (%d items) over result.new_items (%d items)",
            len(captured),
            len(chain),
        )
        chain = captured
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
        "moodle",
        "wordpress",
        "tomcat",
        "nginx",
        "apache",
        "java",
        "php",
        "python",
        "nodejs",
        "react",
        "vue",
        "mysql",
        "postgresql",
        "mongo",
        "redis",
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
    # F203.K — extract + hooks-captured fallback in one place (shared with the
    # investigate report so both agree on what the agent actually ran).
    chain = chain_from_result(result)

    # F203.H — KRYON_WRITEBACK_DEBUG=1 enables verbose dump of item shapes
    # and extracted chain for debugging SDK item structure changes.
    if os.environ.get("KRYON_WRITEBACK_DEBUG", "").lower() in ("1", "true", "yes"):
        logger.warning("WB-DEBUG: new_items count: %d", len(new_items))
        for i, item in enumerate(new_items[:10]):
            item_attr_type = getattr(item, "type", "?")
            raw_cls = type(getattr(item, "raw_item", None)).__name__
            logger.warning(
                "WB-DEBUG: item[%d] type=%s raw_cls=%s name=%s",
                i,
                item_attr_type,
                raw_cls,
                getattr(getattr(item, "raw_item", None), "name", None),
            )
        _cap = getattr(result, "_captured_chain", None)
        logger.warning(
            "WB-DEBUG: final chain: %d tool calls (captured=%s)",
            len(chain),
            len(_cap) if isinstance(_cap, list) else "n/a",
        )

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

    # T4-M2: add_experience() embeds via sentence-transformers/ChromaDB, which on an
    # air-gapped box downloads an ~80MB ONNX model or hangs ~60s at session tail — a
    # hang is not an exception, so the try/except below never caught it and investigate
    # blocked on exit. Run it in a DAEMON thread (does not block interpreter exit) and
    # skip if it overruns the wall-clock timeout.
    import threading

    _timeout = float(os.environ.get("KRYON_WRITEBACK_TIMEOUT_S", "10"))
    _box: dict[str, Any] = {}

    def _persist() -> None:
        try:
            _box["id"] = add_experience(experience)
        except Exception as e:  # noqa: BLE001
            _box["error"] = e

    _t = threading.Thread(target=_persist, name="kryon-writeback", daemon=True)
    _t.start()
    _t.join(timeout=_timeout)

    if _t.is_alive():
        logger.warning("write-back skipped: embedding persistence exceeded %.0fs (air-gapped/no model?)", _timeout)
        return None
    if "error" in _box:
        logger.warning("write-back persistence failed: %s", _box["error"])
        return None
    exp_id = _box.get("id")

    logger.info("investigate write-back: experience %s persisted (outcome=%s, chain=%d)", exp_id, outcome, len(chain))

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
