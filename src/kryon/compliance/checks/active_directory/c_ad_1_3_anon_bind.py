"""AD-1.3 — Anonymous LDAP bind is rejected (no user/domain enum).

Legacy misconfig: some AD deployments still allow anonymous binds that
reveal usernames, group memberships, and computer accounts. This is
the first-move of virtually every internal penetration test.

We probe with an anonymous simple bind and look for a "Success" result.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.active_directory._helpers import (
    ad_env, check_tool, tool_missing_error,
)
from kryon.compliance.runner import register_check, run_cmd


class _AnonBindCheck:
    control_id = "AD-1.3"
    control_title = "Anonymous LDAP bind is rejected (no enumeration)"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "On DC: Group Policy → Default Domain Controllers Policy → "
        "Security Options → 'Network access: Allow anonymous SID/Name "
        "translation' = Disabled. "
        "Also set `dsHeuristics` char #7 to `2` to block anonymous ops. "
        "PowerShell: `Set-ADObject -Identity 'CN=Directory Service,...' "
        "-Replace @{dSHeuristics='0000002'}`"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        _, _, _, dc = ad_env()
        dc = dc or ctx.host

        if not check_tool(ctx, "ldapsearch"):
            return tool_missing_error(
                self.control_id, self.control_title, self.section,
                self.severity, self.remediation_static, ctx.host, t0,
                tool="ldapsearch", install_hint="apt install ldap-utils",
            )

        # Anonymous bind (-x, no -D / -w), query rootDSE for anything useful
        cmd = (
            f"ldapsearch -x -H ldap://{dc}:389 -b '' -s base "
            f"namingContexts supportedLDAPVersion 2>&1 | head -15"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        # Markers
        anon_ok = ("result: 0 Success" in out
                   or ("namingContexts:" in out and "result:" in out))
        rejected_markers = [
            "Operations error",
            "000004DC",  # NT_STATUS_LOGON_FAILURE
            "Strong(er) authentication required",
            "Server is unwilling to perform",
            "result: 1 ",
            "result: 49 Invalid credentials",
        ]
        rejected = any(m in out for m in rejected_markers)

        if not (anon_ok or rejected):
            # Likely can't reach the DC at all
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not determine anon bind state",
                                 "rc": rc},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        issues: list[str] = []
        if anon_ok and not rejected:
            issues.append("Anonymous LDAP bind succeeded — rootDSE accessible without auth")

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={
                "anonymous_bind_accepted": anon_ok and not rejected,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AnonBindCheck()
register_check(CHECK)
