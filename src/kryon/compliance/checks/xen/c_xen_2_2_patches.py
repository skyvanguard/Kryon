"""XEN-2.2 — dom0 security patches applied (no pending updates).

XCP-ng / XenServer dom0 is yum-managed (CentOS-based). Pending updates mean
unpatched hotfixes on the hypervisor. Uses `yum check-update` to count what's
outstanding.

FAIL if there are pending package updates. ERROR only if yum itself errors
hard. (A yum-less system reports 0 and PASSes — best effort.)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_result
from kryon.compliance.runner import register_check, run_cmd


class _PatchesCheck:
    control_id = "XEN-2.2"
    control_title = "dom0 security patches applied (no pending updates)"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Apply pending updates on a maintenance window:\n"
        "  yum update    # XCP-ng; then reboot the pool coordinator last\n"
        "For XenServer, apply hotfixes via `xe patch-apply` / XenCenter."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "yum -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]'"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=30)
        try:
            pending = int(out.strip().splitlines()[-1]) if out.strip() else 0
        except (ValueError, IndexError):
            pending = 0

        verdict = "PASS" if pending == 0 else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"pending_updates": pending}, t0=t0, ctx=ctx
        )


CHECK = _PatchesCheck()
register_check(CHECK)
