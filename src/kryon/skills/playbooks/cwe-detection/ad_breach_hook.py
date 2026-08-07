"""Active Directory BREACH pre_hook — deterministic initial-access foothold.

Thin adapter: the runner loads this file by path (isolated module, no package
context), so it uses an ABSOLUTE import of the importable, unit-tested library
(``kryon.tools.lateral_movement.ad_breach``) rather than a relative import.

Runs the breach chain (recon -> user-enum -> AS-REP roast -> common-password
spray) BEFORE the LLM and injects the recovered foothold credentials as
authoritative context. Complements the F205 takeover chain
(``ad_roast_hook.py``): breach obtains the FIRST credential, roast escalates it
to Domain Admin. See ``ad_breach.py`` for the full contract + safety notes.
"""

from __future__ import annotations

from typing import Any


def run(ctx: dict[str, Any]) -> str:
    from kryon.tools.lateral_movement.ad_breach import run_breach  # noqa: PLC0415

    return run_breach(ctx)
