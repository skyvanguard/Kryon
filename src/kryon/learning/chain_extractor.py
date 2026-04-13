"""
Chain extractor — parse a session's message history into a structured
attack chain with outcome classification.

Input shape is the same `conversation_input` that the REPL keeps across
turns: a list of dicts with `role`, `content`, and tool-call fields. We
accept several variations because the SDK switches between OpenAI-style
tool_calls and Responses-API style items.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

logger = logging.getLogger(__name__)


# Signals we grep for when classifying the outcome
_SHELL_SIGNALS = [
    r"\buid=\d+",
    r"\bwhoami\b",
    r"\b/bin/(bash|sh)\b",
    r"\broot@\w+",
    r"\bshell\s+gained\b",
    r"\breverse shell\b",
]
_FLAG_SIGNALS = [
    r"flag\{[^}]{3,}\}",
    r"HTB\{[^}]{3,}\}",
    r"THM\{[^}]{3,}\}",
    r"picoCTF\{[^}]{3,}\}",
]
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DIR_COUNT_RE = re.compile(r"(?i)found\s+(\d+)\s+(?:directories|paths)")


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for c in content:
            if isinstance(c, dict):
                parts.append(c.get("text") or c.get("content") or "")
            elif isinstance(c, str):
                parts.append(c)
        return "\n".join(p for p in parts if p)
    if content is None:
        return ""
    return str(content)


def _iter_messages(history: Iterable[Any]) -> Iterable[dict[str, Any]]:
    """Yield message-shaped dicts from whatever the REPL stores."""
    for item in history:
        if not item:
            continue
        if isinstance(item, dict):
            yield item
        elif hasattr(item, "to_dict"):
            try:
                yield item.to_dict()  # type: ignore[attr-defined]
            except Exception:
                yield {"role": "unknown", "content": str(item)}
        else:
            yield {"role": "unknown", "content": str(item)}


def _extract_tool_calls(history: Iterable[Any]) -> list[dict[str, Any]]:
    """Best-effort extraction of tool calls + their outputs from history.

    Supports two shapes:
    - OpenAI chat messages with `tool_calls` on the assistant message and
      a separate `{"role":"tool","tool_call_id":...,"content":...}` for
      results.
    - Items with a `type` field like `function_call` / `tool_call` /
      `function_call_output`.
    """
    pending: dict[str, dict[str, Any]] = {}
    chain: list[dict[str, Any]] = []

    for msg in _iter_messages(history):
        role = msg.get("role") or msg.get("type")

        # Assistant with OpenAI-style tool_calls
        tcs = msg.get("tool_calls")
        if tcs and isinstance(tcs, list):
            for tc in tcs:
                try:
                    tc_id = tc.get("id") or tc.get("tool_call_id")
                    fn = tc.get("function") or {}
                    name = fn.get("name") or tc.get("name") or "?"
                    args = fn.get("arguments") or tc.get("arguments") or ""
                    pending[tc_id] = {"tool": name, "args": args, "status": "pending", "output": ""}
                except Exception:
                    continue

        # Tool result messages
        if role == "tool" and msg.get("tool_call_id"):
            tc_id = msg.get("tool_call_id")
            call = pending.get(tc_id)
            out = _content_text(msg.get("content"))
            if call:
                call["status"] = "error" if ("error" in out.lower()[:120]) else "ok"
                call["output"] = out[:2000]
                chain.append(call)
                pending.pop(tc_id, None)
            else:
                chain.append(
                    {"tool": "unknown", "args": "", "status": "orphan-output", "output": out[:2000]}
                )

        # Responses-API style items: function_call / function_call_output
        item_type = msg.get("type")
        if item_type in ("function_call", "tool_call"):
            tc_id = msg.get("call_id") or msg.get("id")
            name = msg.get("name") or "?"
            args = msg.get("arguments") or ""
            pending[tc_id] = {"tool": name, "args": args, "status": "pending", "output": ""}
        elif item_type in ("function_call_output", "tool_call_output"):
            tc_id = msg.get("call_id") or msg.get("id")
            call = pending.get(tc_id)
            out = _content_text(msg.get("output") or msg.get("content"))
            if call:
                call["status"] = "error" if ("error" in out.lower()[:120]) else "ok"
                call["output"] = out[:2000]
                chain.append(call)
                pending.pop(tc_id, None)

    # Flush pending-without-output (interrupted tool calls)
    for tc_id, call in pending.items():
        call["status"] = "no-output"
        chain.append(call)

    return chain


def _classify_outcome(text: str, chain: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """Return (outcome, signals) based on patterns in the collected text."""
    lower = text.lower()

    signals: dict[str, Any] = {
        "shell_gained": False,
        "flag_found": False,
        "cve_confirmed": [],
        "directories_found": 0,
    }

    for pat in _SHELL_SIGNALS:
        if re.search(pat, text, re.IGNORECASE):
            signals["shell_gained"] = True
            break

    for pat in _FLAG_SIGNALS:
        if re.search(pat, text):
            signals["flag_found"] = True
            break

    cves = sorted(set(_CVE_RE.findall(text)))
    if cves:
        signals["cve_confirmed"] = cves

    dir_match = _DIR_COUNT_RE.search(text)
    if dir_match:
        try:
            signals["directories_found"] = int(dir_match.group(1))
        except Exception:
            pass

    # If no explicit dir count, approximate from gobuster-style lines
    if signals["directories_found"] == 0:
        dir_hits = len(re.findall(r"^\s*/\S+\s+\(Status: 2\d\d", text, re.MULTILINE))
        signals["directories_found"] = dir_hits

    # Outcome classification
    if signals["shell_gained"] or signals["flag_found"]:
        outcome = "success"
    elif chain and any(c.get("status") == "ok" for c in chain) and (signals["cve_confirmed"] or signals["directories_found"] >= 3):
        outcome = "partial"
    elif chain:
        outcome = "recon-only"
    else:
        outcome = "fail"
    return outcome, signals


def extract_chain_from_history(
    history: Iterable[Any],
    *,
    agent_path: list[str] | None = None,
) -> dict[str, Any]:
    """Parse the full message history of one engagement into a chain dict
    ready to be fed into `add_experience`.
    """
    history_list = list(history)
    chain = _extract_tool_calls(history_list)

    # Concatenate all text we saw for pattern matching
    text_chunks: list[str] = []
    for msg in _iter_messages(history_list):
        text_chunks.append(_content_text(msg.get("content")))
        if msg.get("output"):
            text_chunks.append(str(msg["output"]))
    for step in chain:
        if step.get("output"):
            text_chunks.append(step["output"])
    full_text = "\n".join(text_chunks)

    outcome, signals = _classify_outcome(full_text, chain)

    # Build a rich summary: target + tool chain + outcome + key stats
    tool_names = [step.get("tool", "?") for step in chain if step.get("tool")]
    # De-dup consecutive same-tool calls
    deduped: list[str] = []
    for t in tool_names:
        clean = t.rsplit(":", 1)[-1] if ":" in t else t  # strip namespace
        if not deduped or deduped[-1] != clean:
            deduped.append(clean)

    # Extract target from text if possible
    import re as _re

    target_match = _re.search(r"Nmap scan report for\s+(\S+)", full_text)
    target_host = target_match.group(1) if target_match else ""

    chain_str = " → ".join(deduped) if deduped else "no tools"
    stats_bits: list[str] = []
    if signals.get("cve_confirmed"):
        stats_bits.append(f"{len(signals['cve_confirmed'])} CVEs")
    if signals.get("directories_found"):
        stats_bits.append(f"{signals['directories_found']} dirs")
    if signals.get("shell_gained"):
        stats_bits.append("shell")
    if signals.get("flag_found"):
        stats_bits.append("flag")
    stats_str = f" [{', '.join(stats_bits)}]" if stats_bits else ""

    summary = f"{target_host}: {chain_str} [{outcome}{stats_str}]" if target_host else f"{chain_str} [{outcome}{stats_str}]"

    return {
        "chain": chain,
        "outcome": outcome,
        "outcome_signals": signals,
        "agent_path": agent_path or [],
        "summary": summary,
    }
