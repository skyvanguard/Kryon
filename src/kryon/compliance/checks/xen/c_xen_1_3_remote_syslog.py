"""XEN-1.3 — Remote syslog destination configured.

XenServer / XCP-ng hosts have limited local log retention, so logs should be
forwarded to a SIEM. The host `logging` parameter carries the
`syslog_destination`; read via `xe host-list params=logging`.

FAIL if no syslog destination is set. ERROR if `xe` fails (not a Xen host).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _RemoteSyslogCheck:
    control_id = "XEN-1.3"
    control_title = "Remote syslog destination configured"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Forward dom0 logs to your SIEM (per host):\n"
        "  xe host-param-set uuid=<host-uuid> logging:syslog_destination=siem.corp\n"
        "  xe host-syslog-reconfigure host-uuid=<host-uuid>"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "xe host-list params=logging 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="xe call failed (Xen host?)")

        m = re.search(r"syslog_destination:\s*(\S+)", out)
        dest = m.group(1).strip() if m else ""
        configured = bool(dest) and dest.lower() not in ("", "none", "<none>")
        verdict = "PASS" if configured else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"syslog_destination": dest or "(none)"},
            t0=t0,
            ctx=ctx,
        )


CHECK = _RemoteSyslogCheck()
register_check(CHECK)
