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
        ok, exp_id = close_and_save_experience("")  # use chain_extractor's auto-summary
        if ok and exp_id:
            print(f"\n✅ Experience auto-saved: {exp_id}")
            _try_synthesize_skill_draft(exp_id)
        else:
            logger.debug("auto_extract: nothing to save (no target or no tools)")
    except Exception as e:
        logger.debug("auto_extract: failed: %s", e)


def _try_synthesize_skill_draft(exp_id: str) -> None:
    """Best-effort: turn the persisted experience into a draft skill.

    Runs after the experience itself was saved. Failures here NEVER
    block exit — if synthesizer / draft_writer / chromadb is unavailable
    we just log and move on. The user only sees the drafts/path message
    when a draft was actually produced (otherwise silence).
    """
    try:
        from kryon.learning import get_experience
        from kryon.learning.draft_writer import try_synthesize_and_persist
    except Exception as e:
        logger.debug("auto_extract: synthesizer imports unavailable: %s", e)
        return

    try:
        experience = get_experience(exp_id)
        if not experience:
            return
        draft_path = try_synthesize_and_persist(experience)
        if draft_path is not None:
            print(f"📝 Skill draft synthesized: {draft_path}")
            print(f"   Review with: /skill review {draft_path.stem}")
    except Exception as e:
        logger.debug("auto_extract: synthesizer step failed: %s", e)
