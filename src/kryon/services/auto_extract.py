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

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def checkpoint_session(message_history: list, session_id: str | None = None) -> None:
    """Persist the live message history to disk so a mid-audit crash
    (DeepSeek 5xx, network drop, balance exhaustion) doesn't lose
    findings. Atomic write via tmp+rename.

    Called periodically from add_to_message_history every N turns.
    Tunable via KRYON_CHECKPOINT_EVERY (default 50). Best-effort —
    never raises; failures only log at debug level.
    """
    try:
        if not message_history:
            return
        sid = session_id or os.environ.get("KRYON_SESSION_ID") or "default"
        ckpt_dir = Path.home() / ".kryon" / "sessions" / sid
        ckpt_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = ckpt_dir / "checkpoint.json.tmp"
        ckpt_path = ckpt_dir / "checkpoint.json"
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "session_id": sid,
                    "checkpoint_ts": datetime.now(timezone.utc).isoformat(),
                    "message_count": len(message_history),
                    "messages": message_history,
                },
                f,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        tmp_path.replace(ckpt_path)
        logger.debug("checkpoint saved: %s (%d msgs)", ckpt_path, len(message_history))
    except Exception as e:  # noqa: BLE001 — never block the audit
        logger.debug("checkpoint_session failed: %s", e)


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
