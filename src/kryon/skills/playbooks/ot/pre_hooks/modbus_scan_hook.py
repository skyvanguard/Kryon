"""Pre_hook wrapper — deterministic Modbus/TCP probe (modbus-audit skill).

Runs ``kryon.tools.ot.modbus_scan`` against ctx['host'] on the standard
Modbus port (502) and injects the result as ground truth. Read-only:
``attempt_write`` is left False — a stray Write Single Coil can actuate
physical equipment.
"""

from __future__ import annotations

from typing import Any

from kryon.tools.ot.modbus_scan import modbus_scan
from kryon.tools.ot.pre_hook_format import format_ot_result, normalise_host

_PORT = 502


def run(ctx: dict[str, Any]) -> str:
    host = normalise_host(ctx.get("host") or ctx.get("target") or "")
    if not host:
        return "[modbus-scan] no target in ctx (neither host nor target set)"
    result = modbus_scan(host, port=_PORT, attempt_write=False)
    return format_ot_result(result, protocol="Modbus/TCP")
