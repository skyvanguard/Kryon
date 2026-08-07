"""Pre_hook wrapper — deterministic MQTT broker probe (mqtt-industrial-audit skill).

Runs ``kryon.tools.ot.mqtt_industrial_audit`` against ctx['host'] on the
standard MQTT port (1883) and injects the result. Read-only: anonymous
CONNECT + ``$SYS/#`` subscribe, never a PUBLISH.
"""

from __future__ import annotations

from typing import Any

from kryon.tools.ot.mqtt_industrial_audit import mqtt_industrial_audit
from kryon.tools.ot.pre_hook_format import format_ot_result, normalise_host

_PORT = 1883


def run(ctx: dict[str, Any]) -> str:
    host = normalise_host(ctx.get("host") or ctx.get("target") or "")
    if not host:
        return "[mqtt-audit] no target in ctx (neither host nor target set)"
    result = mqtt_industrial_audit(host, port=_PORT)
    return format_ot_result(result, protocol="MQTT")
