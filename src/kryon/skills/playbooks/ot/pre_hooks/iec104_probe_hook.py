"""Pre_hook wrapper — deterministic IEC 60870-5-104 probe (iec104-audit skill).

Runs ``kryon.tools.ot.iec104_probe`` against ctx['host'] on the standard
IEC-104 port (2404) and injects the result. Read-only: STARTDT/TESTFR
session control only, never an I-format command frame.
"""

from __future__ import annotations

from typing import Any

from kryon.tools.ot.iec104_probe import iec104_probe
from kryon.tools.ot.pre_hook_format import format_ot_result, normalise_host

_PORT = 2404


def run(ctx: dict[str, Any]) -> str:
    host = normalise_host(ctx.get("host") or ctx.get("target") or "")
    if not host:
        return "[iec104-probe] no target in ctx (neither host nor target set)"
    result = iec104_probe(host, port=_PORT)
    return format_ot_result(result, protocol="IEC 60870-5-104")
