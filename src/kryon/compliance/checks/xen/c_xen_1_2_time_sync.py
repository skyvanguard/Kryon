"""XEN-1.2 — dom0 time synchronization active.

Consistent time across a Xen pool is required for live migration, TLS/cert
validation, and cross-host log correlation. Verifies NTP is enabled and the
clock is synchronized via timedatectl.

FAIL if NTP is off or the clock is not synchronized. ERROR if timedatectl is
unavailable.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _TimeSyncCheck:
    control_id = "XEN-1.2"
    control_title = "dom0 time synchronization active"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Enable NTP on every pool host:\n"
        "  timedatectl set-ntp true    # or configure chrony with a trusted source\n"
        "All hosts in a pool must use the same time source."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "timedatectl show --property=NTP --property=NTPSynchronized 2>/dev/null; timedatectl 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=6)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="timedatectl unavailable")

        low = out.lower()
        ntp_active = "ntp=yes" in low or "ntp service: active" in low
        synchronized = "ntpsynchronized=yes" in low or "system clock synchronized: yes" in low
        verdict = "PASS" if (ntp_active and synchronized) else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"ntp_active": ntp_active, "clock_synchronized": synchronized},
            t0=t0,
            ctx=ctx,
        )


CHECK = _TimeSyncCheck()
register_check(CHECK)
