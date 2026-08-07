"""Pre_hook wrapper — deterministic DNP3 probe (dnp3-audit skill).

Runs ``kryon.tools.ot.dnp3_probe`` against ctx['host'] on the standard
DNP3 port (20000) and injects the result. Read-only: a single Read
Class 0 request, never a control function code.
"""

from __future__ import annotations

from typing import Any

from kryon.tools.ot.dnp3_probe import dnp3_probe
from kryon.tools.ot.pre_hook_format import format_ot_result, normalise_host

_PORT = 20000


def run(ctx: dict[str, Any]) -> str:
    host = normalise_host(ctx.get("host") or ctx.get("target") or "")
    if not host:
        return "[dnp3-probe] no target in ctx (neither host nor target set)"
    result = dnp3_probe(host, port=_PORT)
    return format_ot_result(result, protocol="DNP3")
