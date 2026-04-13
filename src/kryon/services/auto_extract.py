"""
Auto-extract experiences on REPL exit.

Ported from Claude Code's `services/extractMemories/extractMemories.ts`.

On exit, if the session had tool calls and `/experiences close` was not
already called manually, mine the conversation and persist an experience.

Usage (in the REPL exit handler):
    try:
        from kryon.services.auto_extract import auto_extract_on_exit
        auto_extract_on_exit()
    except Exception:
        pass  # never block exit
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def auto_extract_on_exit() -> None:
    """Mine the current session into an experience, if worthwhile.

    Safe to call unconditionally — skips silently when:
    - No agent histories exist
    - No tool calls were made (pure conversation)
    - `/experiences close` was already called manually
    - The learning module is unavailable (e.g., ChromaDB not installed)
    """
    try:
        from kryon.repl.commands.experiences import (
            close_and_save_experience,
            was_already_closed,
        )
    except Exception as e:
        logger.debug("auto_extract: import failed: %s", e)
        return

    if was_already_closed():
        logger.debug("auto_extract: skipped — /experiences close already ran")
        return

    try:
        ok, exp_id = close_and_save_experience("auto-captured on exit")
        if ok and exp_id:
            print(f"\n✅ Experience auto-saved: {exp_id}")
        else:
            logger.debug("auto_extract: nothing to save (no target or no tools)")
    except Exception as e:
        logger.debug("auto_extract: failed: %s", e)
