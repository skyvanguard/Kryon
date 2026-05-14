"""Enable red-team-gated imports for tests under ``tests/state/``.

Some checkpoint tests import EngagementGoal / PlanPhase from
``kryon.tools.autonomous`` whose ``__init__.py`` re-exports gated
evasion symbols. CI sets the env var; local runs need this mirror.
"""

from __future__ import annotations

import os

os.environ.setdefault("KRYON_RED_TEAM", "true")
