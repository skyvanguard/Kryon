"""FGT-1.6 — At most 2 admin accounts with `super_admin` profile.

Super-admin is the FortiGate equivalent of root. Sprawl ("everyone in IT
got super_admin so they wouldn't bug me about permissions") is the most
common audit finding. CIS Fortinet recommends <= 2 accounts. We flag
anything above 2.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MAX_SUPER_ADMINS = 2


class _SuperAdminCountCheck:
    control_id = "FGT-1.6"
    control_title = f"At most {_MAX_SUPER_ADMINS} admin accounts with super_admin profile"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Replace casual super-admins with role-scoped accprofiles:\n"
        "  config system accprofile\n"
        "    edit \"netops_readonly\"\n"
        "      set scope vdom\n"
        "      set sysgrp read\n"
        "      set fwgrp read\n"
        "      ...\n"
        "    next\n"
        "  end\n"
        "Then reassign:\n"
        "  config system admin\n"
        "    edit <user>\n"
        "      set accprofile \"netops_readonly\"\n"
        "    next\n"
        "  end\n"
        "Keep super_admin to the break-glass account + on-call backup only."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system admin"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read admin config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        super_admins: list[str] = []
        all_admins: list[str] = []
        for m in re.finditer(
            r'edit\s+"([^"]+)"\s*(.*?)\bnext\b',
            out,
            re.S,
        ):
            name = m.group(1)
            body = m.group(2)
            all_admins.append(name)
            prof = re.search(r'set\s+accprofile\s+"([^"]+)"', body)
            if prof and prof.group(1) == "super_admin":
                super_admins.append(name)
            elif not prof:
                # Default profile when not set is super_admin on FortiOS.
                super_admins.append(name)

        issues: list[str] = []
        if len(super_admins) > _MAX_SUPER_ADMINS:
            issues.append(
                f"{len(super_admins)} super_admin accounts > {_MAX_SUPER_ADMINS} threshold"
            )

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed={
                "all_admins": sorted(all_admins),
                "super_admins": sorted(super_admins),
                "super_admin_count": len(super_admins),
                "threshold": _MAX_SUPER_ADMINS,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SuperAdminCountCheck()
register_check(CHECK)
