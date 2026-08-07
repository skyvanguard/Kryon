"""XEN-2.1 — XCP-ng / XenServer version is supported (not EOL).

Running an end-of-life hypervisor means no security hotfixes. Reads the host
`software-version` via `xe host-list`. XCP-ng 8.0/8.1 and every 7.x release
are EOL; 8.2 (LTS) and later are supported. (Citrix Hypervisor / XenServer
tracks the same 8.x line.)

FAIL if product_version < 8.2. ERROR if `xe` fails / version unparseable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_MIN_SUPPORTED = (8, 2)


class _VersionCheck:
    control_id = "XEN-2.1"
    control_title = "XCP-ng / XenServer version supported (not EOL)"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Upgrade to a supported release (XCP-ng 8.2 LTS or 8.3+, or a current\n"
        "XenServer 8). Follow the official pool-upgrade / rolling-pool-upgrade\n"
        "procedure; apply all hotfixes after."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "xe host-list params=software-version 2>/dev/null | head -5"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="xe call failed (Xen host?)")

        m = re.search(r"product_version:\s*(\d+)\.(\d+)", out)
        if not m:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="product_version unparseable")

        major, minor = int(m.group(1)), int(m.group(2))
        verdict = "PASS" if (major, minor) >= _MIN_SUPPORTED else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"product_version": f"{major}.{minor}"},
            t0=t0,
            ctx=ctx,
        )


CHECK = _VersionCheck()
register_check(CHECK)
