"""AD-3.1 — Domain Admins group membership <= 5 (banking profile).

Banking audit rule: Domain Admins should have at most 5 permanent
members. In engagement after engagement we find 20-40+ accounts as DA,
many never used. Compromise of any single DA = full domain.

We enumerate CN=Domain Admins,CN=Users,<base_dn> members via LDAP.
"""

from __future__ import annotations

import re
import shlex
import time

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    missing_creds_error,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

DA_THRESHOLD = 5  # banking default


class _DomainAdminsCheck:
    control_id = "AD-3.1"
    control_title = "Domain Admins group has <= 5 active members"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Remove stale/unused members from Domain Admins. Use Just-In-Time "
        "admin (Microsoft PAM or Bloodhound-driven cleanup). "
        "Also audit Enterprise Admins, Schema Admins (should be empty "
        "outside schema updates), Administrators (local DC), "
        "Account Operators, Backup Operators — all effectively DA-equivalent."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        domain, user, pwd, dc = ad_env()
        dc = dc or ctx.host

        if not (domain and user and pwd and dc):
            return missing_creds_error(
                self.control_id,
                self.control_title,
                self.section,
                self.severity,
                self.remediation_static,
                ctx.host,
                t0,
            )

        if not check_tool(ctx, "ldapsearch"):
            return tool_missing_error(
                self.control_id,
                self.control_title,
                self.section,
                self.severity,
                self.remediation_static,
                ctx.host,
                t0,
                tool="ldapsearch",
                install_hint="apt install ldap-utils",
            )

        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        # Get member list of Domain Admins (CN=Domain Admins,CN=Users,<base>)
        da_dn = f"CN=Domain Admins,CN=Users,{base_dn}"
        cmd = f"ldapsearch -x -H ldap://{shlex.quote(dc)} -D {shlex.quote(user)} -w {shlex.quote(pwd)} -b {shlex.quote(da_dn)} -s base member 2>&1"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if "result: 0 Success" not in out and rc != 0:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd.replace(pwd, "***"),
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "LDAP query for Domain Admins failed", "rc": rc},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        members = re.findall(r"^member:\s*(CN=[^,\n]+)", out, re.M)
        count = len(members)

        issues: list[str] = []
        if count > DA_THRESHOLD:
            issues.append(f"Domain Admins has {count} members (threshold {DA_THRESHOLD})")

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd.replace(pwd, "***"),
            evidence_stdout=(
                f"Domain Admins members ({count}):\n"
                + "\n".join(f"  {m}" for m in members[:15])
                + ("\n  ..." if count > 15 else "")
            )[:2048],
            evidence_stderr=err[:256],
            evidence_parsed={
                "member_count": count,
                "threshold": DA_THRESHOLD,
                "members_sample": members[:10],
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _DomainAdminsCheck()
register_check(CHECK)
