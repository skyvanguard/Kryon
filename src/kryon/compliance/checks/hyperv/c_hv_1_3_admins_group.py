"""HV-1.3 — 'Hyper-V Administrators' group is not overly broad.

Members of the local 'Hyper-V Administrators' group get full control of every
VM (create/delete/console/export) without being OS administrators. Adding a
broad principal (Everyone, Authenticated Users, Domain Users, BUILTIN\\Users)
effectively hands VM control to the whole environment.

FAIL if the group includes a broad principal. ERROR if the WinRM call fails.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_BROAD = ("everyone", "authenticated users", "domain users", "\\users")


class _AdminsGroupCheck:
    control_id = "HV-1.3"
    control_title = "'Hyper-V Administrators' group not overly broad"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Remove broad principals from the group (PowerShell, admin):\n"
        "  Remove-LocalGroupMember -Group 'Hyper-V Administrators' -Member '<broad>'\n"
        "Grant it only to named VM operators; reserve local admin for OS tasks."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "powershell -nop -c \"@(Get-LocalGroupMember -Group 'Hyper-V Administrators' "
            "-ErrorAction SilentlyContinue | ForEach-Object Name) -join ';'\""
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=20)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        members = [m.strip() for m in out.strip().split(";") if m.strip()]
        broad = sorted({m for m in members if any(b in m.lower() for b in _BROAD)})
        verdict = "FAIL" if broad else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"members": members, "broad_principals": broad},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AdminsGroupCheck()
register_check(CHECK)
