"""IOS-1.1 — VTY lines do not allow telnet.

CIS Cisco Benchmark: `transport input telnet` (or `all`) on the VTY lines
exposes the device's admin session in cleartext. VTY access must be SSH-only.

FAIL if any `transport input` line allows telnet or all. PASS otherwise.
ERROR if the output isn't an IOS running-config.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.cisco._common import SHOW_RUN, looks_like_ios, make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_TRANSPORT_RE = re.compile(r"transport input ([^\n\r]+)", re.IGNORECASE)


class _VtySshCheck:
    control_id = "IOS-1.1"
    control_title = "VTY lines do not allow telnet"
    section = "1"
    severity = "HIGH"
    remediation_static = "On each vty range:\n  line vty 0 15\n   transport input ssh"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, SHOW_RUN, shell=True, timeout_s=15)
        if not looks_like_ios(out):
            return make_error(
                self, cmd=SHOW_RUN, out=out, err=err, t0=t0, ctx=ctx, reason="not an IOS running-config (Cisco host?)"
            )

        specs = [s.strip().lower() for s in _TRANSPORT_RE.findall(out)]
        telnet = sorted({s for s in specs if "telnet" in s or "all" in s})
        verdict = "FAIL" if telnet else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=SHOW_RUN,
            out=out[:1024],
            err=err,
            parsed={"telnet_transports": telnet},
            t0=t0,
            ctx=ctx,
        )


CHECK = _VtySshCheck()
register_check(CHECK)
