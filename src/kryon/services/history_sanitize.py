"""Sanitize a conversation history before persisting it to a session (#1 continuity).

The reflective runner (``cli/reflective_runner.py``) injects internal DIRECTIVE
messages as ``{"role": "user", ...}`` — the forced-synthesis prompt, the reflection
nudges, the JSON-repair / premature-rejection blocks. Because the local model is
stateful, those land in ``agent.model.message_history``. Persisting that verbatim
means a *resumed* session REPLAYS the internal scaffolding as if the user had typed
it, and — worse — leaves CONSECUTIVE same-role messages (e.g. ``user, user, ...``)
that some chat templates (jinja) mishandle, stalling the next turn.

``sanitize_history_for_persist`` drops those internal directives so a resumed session
carries only the real user↔assistant conversation, then defensively collapses any
consecutive same-role plain-text messages left behind so the persisted history stays
role-alternating.
"""

from __future__ import annotations

from typing import Any

# Distinctive, stable substrings of every internally-injected user directive in
# reflective_runner.py. Matching is by substring on purpose: the dynamic nudges are
# f-strings, so exact-equality is brittle. These fragments (emojis + fixed Spanish
# phrases) are specific enough that a genuine user/assistant message colliding is
# negligible. If a directive's wording later drifts, the worst case is a MISSED
# filter (degrades to the prior verbatim behaviour) — never a dropped real message.
_INTERNAL_DIRECTIVE_MARKERS: tuple[str, ...] = (
    "El presupuesto de exploración se agotó",  # _FINAL_SYNTHESIS_PROMPT
    "🪞 Reflection forced",  # reflection_msg (chunk budget exhausted)
    "Tu último tool_call fue RECHAZADO por el servidor",  # JSON-invalid nudge
    "🛑 ABANDONÁ por completo ese enfoque",  # reset_nudge (malformed-tool recovery)
    "Tu turno anterior no produjo NINGUNA acción",  # _eo_nudge (empty output)
    "PREMATURE FINAL_OUTPUT REJECTED",  # reject_msg (premature summary gate)
)

# Structural keys that mark a message as a tool/function turn — never merge those.
_STRUCTURAL_KEYS: tuple[str, ...] = ("tool_calls", "tool_call_id", "function_call")


def _content_text(content: Any) -> str:
    """Flatten a message ``content`` (str, or list-of-parts) to plain text for matching."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for p in content:
            parts.append(str(p.get("text", "")) if isinstance(p, dict) else str(p))
        return " ".join(parts)
    return str(content or "")


def _is_internal_directive(msg: Any) -> bool:
    """True when ``msg`` is a runner-injected internal user directive, not real convo."""
    if not isinstance(msg, dict) or msg.get("role") != "user":
        return False
    text = _content_text(msg.get("content"))
    return any(marker in text for marker in _INTERNAL_DIRECTIVE_MARKERS)


def _has_structural_keys(msg: dict[str, Any]) -> bool:
    return any(k in msg for k in _STRUCTURAL_KEYS)


def _merge_consecutive_same_role(history: list[Any]) -> list[Any]:
    """Collapse adjacent same-role PLAIN-TEXT messages into one (join with a blank
    line). Leaves tool/function turns and non-dict items untouched so structured
    turns are never corrupted."""
    out: list[Any] = []
    for msg in history:
        prev = out[-1] if out else None
        mergeable = (
            isinstance(msg, dict)
            and isinstance(prev, dict)
            and msg.get("role")
            and msg.get("role") == prev.get("role")
            and isinstance(msg.get("content"), str)
            and isinstance(prev.get("content"), str)
            and not _has_structural_keys(msg)
            and not _has_structural_keys(prev)
        )
        if mergeable:
            merged = dict(prev)
            a, b = prev.get("content", ""), msg.get("content", "")
            merged["content"] = f"{a}\n\n{b}" if a and b else (a or b)
            out[-1] = merged
        else:
            out.append(msg)
    return out


def sanitize_history_for_persist(history: Any) -> list[Any]:
    """Return a cleaned copy of ``history`` fit to persist for session resume.

    Steps: (1) drop runner-injected internal directives (forced-synthesis / reflection
    nudges); (2) collapse any consecutive same-role plain-text messages the removal
    left adjacent, so the persisted conversation stays role-alternating and a resumed
    turn's chat template doesn't stall on repeated roles. Non-list input → ``[]``;
    non-dict items are preserved as-is."""
    if not isinstance(history, list):
        return []
    filtered = [m for m in history if not _is_internal_directive(m)]
    return _merge_consecutive_same_role(filtered)


def ensure_final_assistant(history: Any, final_output: str | None) -> list[Any]:
    """Guarantee the turn's final assistant answer is present, for continuity.

    A thinking model can return its answer in ``reasoning_content`` with an EMPTY
    ``content`` — the model layer only appends assistant messages whose content is
    non-empty (``openai_chatcompletions.add_to_message_history`` / the ``elif
    assistant_msg.content`` gate), so that answer never lands in ``message_history``.
    Persisting that verbatim leaves a resumed session replaying the user's question
    but NOT the agent's reply.

    When ``final_output`` is non-empty and the most recent (non-tool) assistant
    message doesn't already carry it, append it. No-op when ``final_output`` is empty
    (nothing to preserve) or already captured (avoids duplicating the normal case)."""
    out = list(history) if isinstance(history, list) else []
    if not (final_output and final_output.strip()):
        return out
    fo = final_output.strip()
    for msg in reversed(out):
        if isinstance(msg, dict) and msg.get("role") == "assistant" and not msg.get("tool_calls"):
            content = _content_text(msg.get("content")).strip()
            if content and (fo in content or content in fo):
                return out  # already captured — don't duplicate
            break  # newest assistant doesn't match → append below
    out.append({"role": "assistant", "content": final_output})
    return out


__all__ = ["sanitize_history_for_persist", "ensure_final_assistant"]
