"""Kill-switch — a hard external stop for an autonomous run.

The cage bounds WHERE/WHEN/WHAT the agent acts; the kill-switch bounds HOW MUCH
and lets a human pull the plug mid-run. Checked at the tool-execution layer, it
trips on any of:

  - a kill-file appearing   (KRYON_KILL_FILE=/tmp/kryon.stop — `touch` it to abort)
  - a hard deadline passing (KRYON_DEADLINE=2026-06-18T06:00:00Z)
  - an action budget hit    (KRYON_MAX_ACTIONS=200 — total tool calls this run)

When tripped it raises ``KillSwitchTripped`` (an ``AgentsException``, so it
propagates and STOPS the run rather than being swallowed into an observation the
model could ignore). All three unset → inactive (backward compatible).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from kryon.sdk.agents.exceptions import AgentsException

logger = logging.getLogger(__name__)


class KillSwitchTripped(AgentsException):
    """Raised at the tool layer to hard-stop an autonomous run."""


def _parse_dt(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        logger.warning("killswitch: unparseable KRYON_DEADLINE %r", s)
        return None


class KillSwitch:
    def __init__(self, kill_file: str | None, deadline: datetime | None, max_actions: int | None):
        self.kill_file = kill_file
        self.deadline = deadline
        self.max_actions = max_actions
        self.actions = 0

    def check_and_count(self) -> tuple[bool, str | None]:
        """Increment the action counter and report whether the switch is tripped.
        Returns (tripped, reason)."""
        self.actions += 1
        if self.kill_file and Path(self.kill_file).exists():
            return True, f"kill-file present ({self.kill_file})"
        if self.deadline and datetime.now(timezone.utc) > self.deadline:
            return True, f"deadline passed ({self.deadline.isoformat()})"
        if self.max_actions is not None and self.actions > self.max_actions:
            return True, f"action budget exhausted ({self.max_actions} tool calls)"
        return False, None


_KS: KillSwitch | None = None
_KS_LOADED = False


def get_killswitch() -> KillSwitch | None:
    """Build the kill-switch from env once. All triggers unset → None (inactive)."""
    global _KS, _KS_LOADED
    if _KS_LOADED:
        return _KS
    _KS_LOADED = True
    kill_file = os.environ.get("KRYON_KILL_FILE", "").strip() or None
    deadline = _parse_dt(os.environ.get("KRYON_DEADLINE", ""))
    max_raw = os.environ.get("KRYON_MAX_ACTIONS", "").strip()
    max_actions = int(max_raw) if max_raw.isdigit() else None
    if kill_file is None and deadline is None and max_actions is None:
        _KS = None
        return None
    _KS = KillSwitch(kill_file, deadline, max_actions)
    logger.info(
        "kill-switch ACTIVE: file=%s deadline=%s max_actions=%s", kill_file, deadline, max_actions
    )
    return _KS


def reset_killswitch() -> None:
    """Test hook — force re-read of env + reset the action counter."""
    global _KS, _KS_LOADED
    _KS, _KS_LOADED = None, False
