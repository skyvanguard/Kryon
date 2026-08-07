"""Shared formatting helper for the OT pre_hook wrappers.

The 5 OT skills (modbus/dnp3/iec104/s7/mqtt) each declare a Python
pre_hook (``./pre_hooks/<proto>_hook.py:run``) that runs the matching
deterministic probe from ``kryon.tools.ot.*`` BEFORE the LLM takes the
turn, and injects the result as authoritative ground truth.

This module lives in the importable ``kryon`` package (not under the
skill dir) so the thin wrapper scripts can ``from
kryon.tools.ot.pre_hook_format import normalise_host, format_ot_result``
instead of duplicating the logic. The wrappers themselves are loaded in
isolation by ``pre_hook_runner`` via ``importlib.util.spec_from_file_location``;
a sibling-relative import would have no package context, so the shared
code must be reachable on ``sys.path`` — which the package is.

Both helpers are pure (no I/O of their own beyond what the probe did)
and never raise: a probe that returns an ``error`` field is rendered as
a PASS/unreachable narrative, not an exception.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any
from urllib.parse import urlparse


def normalise_host(raw: str) -> str:
    """Reduce a target string to a bare host for an OT socket probe.

    ``ctx['host']`` may arrive as ``http://10.0.0.5:502/path``,
    ``10.0.0.5:502`` or ``10.0.0.5``. OT probes take a host + a fixed
    protocol port, so we strip scheme, any ``:port`` suffix, and any
    path. Returns ``""`` when nothing host-like remains.
    """
    value = (raw or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        # bare host[:port][/path]
        value = value.split("/", 1)[0]
        # strip a trailing :port but keep IPv6 literals intact
        if value.count(":") == 1:
            value = value.split(":", 1)[0]
    return value.strip()


def format_ot_result(result: Any, *, protocol: str) -> str:
    """Render an OT probe result dataclass as injectable markdown.

    Includes every field via ``dataclasses.asdict`` PLUS the
    ``has_unauth_exposure`` property (which asdict omits because it is a
    property, not a field). The body leads with a one-line verdict so the
    model sees the conclusion before the raw fields.
    """
    fields = dataclasses.asdict(result) if dataclasses.is_dataclass(result) else dict(getattr(result, "__dict__", {}))
    exposed = bool(getattr(result, "has_unauth_exposure", False))
    fields["has_unauth_exposure"] = exposed

    host = fields.get("host", "")
    reachable = bool(fields.get("reachable", False))
    error = fields.get("error", "") or ""

    lines = [f"# 🎯 DETERMINISTIC OT PROBE — {protocol} against {host}"]
    if not reachable:
        why = f" ({error})" if error else ""
        lines.append("")
        lines.append(f"**reachable=False{why} → PASS for this host. {protocol} is not exposed here.**")
    elif exposed:
        lines.append("")
        lines.append(
            f"**🚨 reachable=True AND has_unauth_exposure=True → CRITICAL. "
            f"Anonymous {protocol} access confirmed. Proceed to "
            "`run_compliance_audit` for the full check set.**"
        )
    else:
        lines.append("")
        lines.append(
            "**reachable=True but no unauthenticated exposure detected. "
            "Run `run_compliance_audit` to confirm the remaining checks.**"
        )

    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(fields, ensure_ascii=False, indent=2, default=str))
    lines.append("```")
    return "\n".join(lines)
