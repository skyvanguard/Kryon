"""Enable red-team-gated imports for tests under
``tests/tools/autonomous/``.

The autonomous package's ``__init__.py`` re-exports symbols from
``evasion_autonomy``, which is gated behind ``KRYON_RED_TEAM=true``
(see ``kryon.tools._offensive_gate``). CI sets the env var
explicitly; local runs need this conftest to mirror that.
"""

from __future__ import annotations

import os

os.environ.setdefault("KRYON_RED_TEAM", "true")
