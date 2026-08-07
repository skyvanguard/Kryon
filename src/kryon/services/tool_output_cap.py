"""
Tool output size cap — prevent large tool results from consuming the
entire 32K context window.

Ported from Claude Code's `constants/toolLimits.ts` pattern.

When a tool result exceeds MAX_TOOL_RESULT_CHARS, the full output is
persisted to disk and the model receives a preview (head + tail) with
a pointer to the file. This saves ~80% of context for tool results.

Usage:
    from kryon.services.tool_output_cap import cap_tool_output
    capped = cap_tool_output(raw_output, tool_name="nmap")
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = int(os.environ.get("KRYON_MAX_TOOL_RESULT", "5000"))
TOOL_OUTPUT_DIR = os.environ.get("KRYON_TOOL_OUTPUT_DIR", "/workspace/tool_outputs")

_HEAD_CHARS = 500
_TAIL_CHARS = 1500

# Per-tool-output cap (chars) is window-relative, mirroring the layer-2
# micro-compact budget. The 5k default was tuned for the 4B-local's tight
# window; on a large window (V4 Flash 1M) capping every nmap/nuclei/sqlmap
# output to 5k throws away the raw evidence a capable model chains from
# (dump→creds, endpoints→exploit). Keep the two layers CONSISTENT — the large
# value here must equal micro_compact._LARGE_WINDOW_BUDGET so layer-2 never
# re-trims what layer-1 preserved.
_DEFAULT_TOOL_RESULT_CHARS = 5000
_LARGE_WINDOW_TOOL_RESULT_CHARS = 50000
_LARGE_WINDOW_TOKENS = 500_000


def resolve_tool_result_cap(model_max_tokens: int | None = None, override: str | None = None) -> int:
    """Chars a single tool output may keep before it's saved-to-disk + previewed.

    Precedence: ``KRYON_MAX_TOOL_RESULT`` override > window-relative default
    (>=500k window → 50k, else 5k). A malformed/non-positive override is ignored.
    """
    if override and override.strip():
        try:
            v = int(override.strip())
            if v > 0:
                return v
        except ValueError:
            pass
    if model_max_tokens is None:
        try:
            from kryon.config import settings

            model_max_tokens = settings().model_max_tokens
        except Exception:  # noqa: BLE001 — config must never break context mgmt
            model_max_tokens = 0
    # Window≥500K (V4-1M) OR a capable model → scale the cap to the window instead of
    # the 4B-tight 5000. This fixes the DSpark case: a capable reasoner on a 64K window
    # (<500K) would otherwise get 5000 and lose a sqlmap --dump. A WEAK 4B with a large
    # (128K) window still gets 5000 — capability, not window size, lifts the cap.
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    try:
        capable = is_capable_model()
    except Exception:  # noqa: BLE001 — config must never break context mgmt
        capable = False
    if capable or model_max_tokens >= _LARGE_WINDOW_TOKENS:
        return max(_DEFAULT_TOOL_RESULT_CHARS, min(_LARGE_WINDOW_TOOL_RESULT_CHARS, model_max_tokens // 4))
    return _DEFAULT_TOOL_RESULT_CHARS


# High-value markers: a line carrying one of these is preserved in the preview even
# if it falls in the truncated middle — a hash/flag/cred/key mid-dump used to vanish
# (head 500 + tail 200 only), which is fatal for a THM pwn.
_VALUE_MARKERS = (
    "flag{",
    "password",
    "passwd",
    "nopasswd",
    "uid=",
    "root:",
    "$6$",
    "$1$",
    "$krb5",
    "secret",
    "api_key",
    "apikey",
    "token",
    "-----begin",
    "ntlm",
    "hash",
    "cred",
    "cve-",
)


def _value_lines(content: str, head: str, tail: str, limit: int = 40) -> list[str]:
    """Lines carrying a high-value marker that fall OUTSIDE head/tail — so a secret
    in the truncated middle survives the cap."""
    seen: set[str] = set()
    out: list[str] = []
    for line in content.splitlines():
        low = line.lower()
        if any(m in low for m in _VALUE_MARKERS):
            s = line.strip()
            if s and s not in seen and s not in head and s not in tail:
                seen.add(s)
                out.append(s[:300])
                if len(out) >= limit:
                    break
    return out


def cap_tool_output(content: str, tool_name: str = "tool") -> str:
    """If content exceeds the cap, save to disk and return a preview.

    Args:
        content: Raw tool output string.
        tool_name: Name of the tool (used in the filename).

    Returns:
        Original content if under cap, or truncated preview with file path.
    """
    cap = resolve_tool_result_cap(override=os.environ.get("KRYON_MAX_TOOL_RESULT"))
    if not isinstance(content, str) or len(content) <= cap:
        return content

    # Clean tool name for filesystem
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_name)[:30]
    # PID + uuid suffix so two tools capping in the SAME second (the old HHMMSS-only name)
    # don't overwrite each other's saved output.
    timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
    filename = f"{safe_name}_{timestamp}_{os.getpid()}_{uuid.uuid4().hex[:8]}.txt"
    filepath = Path(TOOL_OUTPUT_DIR) / filename

    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content, encoding="utf-8")
        saved_msg = f"full output saved to {filepath}"
    except Exception as e:
        logger.warning("Failed to save tool output to %s: %s", filepath, e)
        saved_msg = "full output could not be saved"

    total = len(content)
    head = content[:_HEAD_CHARS]
    tail = content[-_TAIL_CHARS:] if _TAIL_CHARS else ""

    value_lines = _value_lines(content, head, tail)
    value_block = ""
    if value_lines:
        value_block = "\n[preserved high-value lines]\n" + "\n".join(value_lines) + "\n"

    return f"{head}\n\n[... {total} chars total — {saved_msg} ...]{value_block}\n{tail}"
