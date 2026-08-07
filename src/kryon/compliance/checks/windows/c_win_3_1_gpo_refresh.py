"""WIN-3.1 — Group Policy refresh interval set ≤ 24 hours.

The default refresh is 90 minutes + a random 30-min skew. Sites can
override this to "manual only" via the registry — that means GPO
changes never propagate until a reboot or `gpupdate /force`. This
check flags refresh intervals over 24 hours (1440 minutes) as FAIL.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _GpoRefreshCheck:
    control_id = "WIN-3.1"
    control_title = "Group Policy refresh interval ≤ 24 hours"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Restore default refresh (90 min + 30 min skew) by clearing the\n"
        "GroupPolicyRefreshTime override:\n"
        "  reg delete HKLM\\Software\\Policies\\Microsoft\\Windows\\System "
        "/v GroupPolicyRefreshTime /f\n"
        "Or via GPO:\n"
        "  Computer Config → Admin Templates → System → Group Policy →\n"
        "    Group Policy refresh interval for computers: Not Configured\n"
        "Without timely GPO refresh, security policy changes (new firewall\n"
        "rules, new audit settings, password complexity bumps) can sit\n"
        "unapplied for days."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "(Get-ItemProperty '
            "-Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\System' "
            '-Name GroupPolicyRefreshTime -ErrorAction SilentlyContinue).GroupPolicyRefreshTime"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ItemNotFound" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        if not value:
            return make_result(
                check=self,
                verdict="PASS",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"refresh_minutes": "default (90+30 skew)"},
                t0=t0,
                ctx=ctx,
            )
        try:
            mins = int(value)
        except ValueError:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason=f"non-numeric: {value!r}")

        verdict = "PASS" if mins <= 1440 else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"refresh_minutes": mins},
            t0=t0,
            ctx=ctx,
        )


CHECK = _GpoRefreshCheck()
register_check(CHECK)
