"""UNF-1.3 — Admin accounts have 2FA enabled.

Mongo `admin` documents carry a `super_mfa` flag (or per-admin `mfa`
sub-document on newer Unifi versions). We dump all admins and require
mfa enabled on all of them.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _Unifi2faCheck:
    control_id = "UNF-1.3"
    control_title = "All Unifi admin accounts have 2FA enabled"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Enable 2FA on each admin account:\n"
        "  Settings → Admins & Users → <admin> → Two-Factor Authentication\n"
        "  → Enroll TOTP (Google Authenticator, 1Password, etc.)\n"
        "Cloud-managed (UI.com SSO) admins inherit MFA from the Ubiquiti\n"
        "account; verify it's enrolled there as well."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.admin.find({}, {name:1, super_mfa:1, mfa:1, "
            "two_factor_auth:1, ui_settings:1}).forEach(function(d){print(JSON.stringify(d))})'"
        )
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
                evidence_parsed={"reason": "could not query mongo"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        admins: list[dict[str, object]] = []
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            super_mfa_m = re.search(r'"super_mfa"\s*:\s*(\w+)', ls)
            two_factor_m = re.search(r'"two_factor_auth"\s*:\s*(\w+)', ls)
            mfa_obj_m = re.search(r'"mfa"\s*:\s*\{[^}]+"enabled"\s*:\s*(\w+)', ls)
            name = name_m.group(1) if name_m else ""
            mfa_on = any([
                (super_mfa_m and super_mfa_m.group(1).lower() == "true"),
                (two_factor_m and two_factor_m.group(1).lower() == "true"),
                (mfa_obj_m and mfa_obj_m.group(1).lower() == "true"),
            ])
            admins.append({"name": name, "mfa_enabled": mfa_on})

        without_mfa = [a["name"] for a in admins if not a["mfa_enabled"]]
        issues: list[str] = []
        if admins and without_mfa:
            issues.append(
                f"{len(without_mfa)}/{len(admins)} admins without 2FA: "
                f"{', '.join(sorted(str(n) for n in without_mfa))}"
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
                "admin_count": len(admins),
                "admins_without_mfa": sorted(str(n) for n in without_mfa),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _Unifi2faCheck()
register_check(CHECK)
