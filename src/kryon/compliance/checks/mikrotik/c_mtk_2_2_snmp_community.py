"""MTK-2.2 — SNMP does not use default communities.

A community named `public` or `private` is the vendor default and grants
read (or write) access to anyone who guesses it. RouterOS ships a `public`
community. Read via `/snmp community print`.

FAIL if a community named public or private exists. ERROR if the command
can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_DEFAULTS = ("public", "private")


class _SnmpCommunityCheck:
    control_id = "MTK-2.2"
    control_title = "SNMP does not use default communities"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Remove default communities and use SNMPv3 (auth+priv):\n"
        "  /snmp community remove [find name=public]\n"
        "Prefer /snmp set enabled=no if SNMP is unused."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "/snmp community print"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="RouterOS CLI call failed")

        # Only inspect data rows (start with an index number), skip Flags/header.
        data = "\n".join(ln for ln in out.splitlines() if re.match(r"^\s*\d+\s", ln)).lower()
        offenders = sorted(d for d in _DEFAULTS if re.search(rf"\b{d}\b", data))
        verdict = "FAIL" if offenders else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"default_communities": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _SnmpCommunityCheck()
register_check(CHECK)
