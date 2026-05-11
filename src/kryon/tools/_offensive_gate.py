"""Opt-in gate for red-team / offensive tool modules.

Modules under `kryon.tools.{anonymity, command_and_control, data_exfiltration,
evasion, lateral_movement, post_exploitation, privilege_escalation}` implement
techniques that are dual-use: legitimate for authorised red-team /
purple-team engagements, hazardous if triggered accidentally during a
blue-team or compliance audit.

They are **disabled by default** so:

  - A curious browser of the repo (a banking security officer reviewing
    Kryon before procurement) does not trip over a `darknet_operations`
    or `log_cleaning` directory loaded at startup.
  - An auto-pipeline that imports `kryon.tools` cannot accidentally
    spin up anything offensive.

To enable:

  export KRYON_RED_TEAM=true

or pass `--red-team` to the CLI (see kryon.cli._original wiring).
"""

from __future__ import annotations

import os

_RED_TEAM_VAR = "KRYON_RED_TEAM"


def is_red_team_enabled() -> bool:
    return os.environ.get(_RED_TEAM_VAR, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def require_red_team(module_name: str) -> None:
    """Raise a clear ImportError if red-team modules are disabled.

    Called at the top of each offensive `__init__.py`. Zero runtime cost
    when the flag is on.
    """
    if is_red_team_enabled():
        return
    raise ImportError(
        f"{module_name} is a red-team / offensive module and is disabled "
        f"by default. To enable, set {_RED_TEAM_VAR}=true or pass "
        f"--red-team to the CLI. See docs/RED_TEAM_MODULES.md."
    )
