"""MTK-1.3 — Bandwidth test server disabled.

The RouterOS bandwidth-test server answers unauthenticated (or weakly
authenticated) throughput tests — a CPU-exhaustion / DoS-amplification
surface that has no place in production. Read via `/tool bandwidth-server
print`.

FAIL if enabled = yes. ERROR if the command can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _BandwidthServerCheck:
    control_id = "MTK-1.3"
    control_title = "Bandwidth test server disabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = "Disable the bandwidth server:\n  /tool bandwidth-server set enabled=no"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "/tool bandwidth-server print"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="RouterOS CLI call failed")

        m = re.search(r"enabled:\s*(yes|no)", out, re.IGNORECASE)
        value = m.group(1).lower() if m else None
        verdict = "FAIL" if value == "yes" else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"bandwidth_server_enabled": value},
            t0=t0,
            ctx=ctx,
        )


CHECK = _BandwidthServerCheck()
register_check(CHECK)
