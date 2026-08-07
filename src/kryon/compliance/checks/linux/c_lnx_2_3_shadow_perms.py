"""LNX-2.3 — /etc/shadow is not world-accessible.

CIS Linux Benchmark: /etc/shadow holds password hashes. If it is world-
readable, any local user can copy the hashes and crack them offline; world-
writable is worse. It must have no "other" permissions (0640/0600/0000).

FAIL if the "other" permission bits are non-zero. ERROR if /etc/shadow can't
be stat'd.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _ShadowPermsCheck:
    control_id = "LNX-2.3"
    control_title = "/etc/shadow is not world-accessible"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Restrict /etc/shadow:\n"
        "  chown root:shadow /etc/shadow && chmod 0640 /etc/shadow   # Debian\n"
        "  chown root:root  /etc/shadow && chmod 0000 /etc/shadow    # RHEL"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "stat -c '%a' /etc/shadow 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        mode = out.strip()
        if not mode.isdigit():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="could not stat /etc/shadow")

        other_bits = int(mode[-1])
        verdict = "PASS" if other_bits == 0 else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"mode": mode, "world_bits": other_bits},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ShadowPermsCheck()
register_check(CHECK)
