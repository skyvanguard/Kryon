"""F150 — R1-tolerant LLM output parsing.

The F12 baseline parser (``_parse_agent_findings`` in cli/engage.py)
assumed a plain instruct-model output: maybe a fenced ``json`` block,
maybe a bare JSON object. Two things break that on a reasoning model
like ``kryon-r1-14b``:

  1. R1 wraps its chain-of-thought in ``<think>...</think>`` tags.
     The actual findings (if any) come after that block.
  2. R1 emits tool-call JSON (``{"name": "...", "arguments": {...}}``)
     mixed with finding JSON. The legacy parser picks up the first
     JSON it sees — which is usually a tool call — and produces zero
     findings.

This module fixes both:

  - ``strip_think_tags(text)`` removes every ``<think>...</think>``
    block (case-insensitive, multiline, supports nested-looking text
    inside).
  - ``extract_finding_json_blocks(text)`` walks every JSON candidate
    in the text and returns only the ones that look like findings
    (have ``severity`` + at least one of ``cwe`` / ``rule_id`` /
    ``message``). Tool-call JSON (``name`` + ``arguments``) is
    explicitly rejected.

The helpers are pure / no I/O; the engage parser composes them.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Match <think>...</think> blocks, case-insensitive, multiline-aware.
# The non-greedy ``.*?`` keeps the closer attached to the nearest opener
# so multiple separate blocks each get stripped.
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)


def strip_think_tags(text: str) -> str:
    """Remove every ``<think>...</think>`` block from ``text``.

    Returns the input unchanged when no tags are present (so calling
    this on a plain instruct-model output is a no-op)."""
    if not text:
        return text
    return _THINK_BLOCK_RE.sub("", text)


def _scan_json_objects(text: str) -> list[Any]:
    """Walk ``text`` and yield every parseable JSON object / array at
    the top level. We don't use a real parser combinator — just
    brace-balanced scan that pairs with json.loads to validate."""
    out: list[Any] = []
    if not text:
        return out

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch not in "{[":
            i += 1
            continue
        # Walk balanced braces (respecting string literals).
        depth = 0
        in_str = False
        escape = False
        opener = ch
        closer = "}" if opener == "{" else "]"
        start = i
        while i < n:
            c = text[i]
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif in_str:
                if c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == opener:
                    depth += 1
                elif c == closer:
                    depth -= 1
                    if depth == 0:
                        candidate = text[start : i + 1]
                        try:
                            parsed = json.loads(candidate)
                            out.append(parsed)
                        except json.JSONDecodeError:
                            pass
                        i += 1
                        break
            i += 1
        else:
            # Reached end without closing — bail out of outer loop.
            break
    return out


def is_finding_shape(obj: Any) -> bool:
    """True when ``obj`` looks like a finding dict (has ``severity``
    AND at least one of ``cwe`` / ``rule_id`` / ``message`` / ``host``)."""
    if not isinstance(obj, dict):
        return False
    if "severity" not in obj:
        return False
    return any(k in obj for k in ("cwe", "rule_id", "message", "host", "title"))


def is_tool_call_shape(obj: Any) -> bool:
    """True when ``obj`` looks like a tool-call JSON (``name`` +
    ``arguments`` / ``parameters``). R1 emits these mixed with text;
    we want to skip them when hunting for findings."""
    if not isinstance(obj, dict):
        return False
    has_name = isinstance(obj.get("name"), str)
    has_args = any(k in obj for k in ("arguments", "parameters", "args"))
    return has_name and has_args


def extract_finding_json_blocks(text: str) -> list[dict[str, Any]]:
    """Return every finding-shaped dict in ``text``. Strips
    ``<think>`` blocks first, then scans for JSON candidates,
    rejecting tool-call shapes.

    Accepts wrapped shapes too:
      - ``[{...}, {...}]`` — bare array of findings.
      - ``{"findings": [{...}]}`` — common LLM envelope.
      - mixed text + JSON — finds every JSON block in the body.
    """
    if not text:
        return []
    cleaned = strip_think_tags(text)
    candidates = _scan_json_objects(cleaned)
    out: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for cand in candidates:
        # Skip tool-call shapes outright.
        if is_tool_call_shape(cand):
            continue
        # Envelope: {"findings": [...]} — common ChatGPT-style.
        if isinstance(cand, dict) and isinstance(cand.get("findings"), list):
            for item in cand["findings"]:
                if is_finding_shape(item):
                    if id(item) in seen_ids:
                        continue
                    seen_ids.add(id(item))
                    out.append(item)
            continue
        # Bare array of findings.
        if isinstance(cand, list):
            for item in cand:
                if is_finding_shape(item):
                    if id(item) in seen_ids:
                        continue
                    seen_ids.add(id(item))
                    out.append(item)
            continue
        # Single finding dict.
        if is_finding_shape(cand):
            out.append(cand)
    return out
