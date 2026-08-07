"""Pre_hook wrapper — deterministic Siemens S7Comm probe (s7-audit skill).

Runs ``kryon.tools.ot.s7_enum`` against ctx['host'] on the standard
S7Comm port (102) and injects the result. Read-only: COTP + S7 setup
handshake and an SZL read, never a write/run-stop control.
"""

from __future__ import annotations

from typing import Any

from kryon.tools.ot.pre_hook_format import format_ot_result, normalise_host
from kryon.tools.ot.s7_enum import s7_enum

_PORT = 102


def run(ctx: dict[str, Any]) -> str:
    host = normalise_host(ctx.get("host") or ctx.get("target") or "")
    if not host:
        return "[s7-enum] no target in ctx (neither host nor target set)"
    result = s7_enum(host, port=_PORT)
    return format_ot_result(result, protocol="Siemens S7Comm")
