"""Enable red-team-gated imports for tests under ``tests/skills/``.

Tests that import ``kryon.tools.autonomous.engagement_goal`` (and similar)
trip the offensive_gate because the autonomous package's ``__init__.py``
re-exports symbols from ``evasion_autonomy``. CI sets the env var
explicitly; local runs need this conftest to mirror that.
"""

from __future__ import annotations

import os

os.environ.setdefault("KRYON_RED_TEAM", "true")
