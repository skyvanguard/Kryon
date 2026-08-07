"""MTK-2.1 — NTP client enabled.

Accurate time on the router underpins log timestamps, certificate validation
and scheduled scripts. RouterOS ships with the NTP client disabled. Read via
`/system ntp client print`.

FAIL if enabled = no. ERROR if the command can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _NtpClientCheck:
    control_id = "MTK-2.1"
    control_title = "NTP client enabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Enable NTP with trusted servers:\n"
        "  /system ntp client set enabled=yes\n"
        "  /system ntp client servers add address=pool.ntp.org"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "/system ntp client print"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="RouterOS CLI call failed")

        m = re.search(r"enabled:\s*(yes|no)", out, re.IGNORECASE)
        value = m.group(1).lower() if m else None
        verdict = "PASS" if value == "yes" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"ntp_enabled": value}, t0=t0, ctx=ctx
        )


CHECK = _NtpClientCheck()
register_check(CHECK)
