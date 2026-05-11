"""FGT-1.4 — 2FA enforced on all admin accounts.

FortiOS supports two-factor for admin login via:
  - FortiToken (Cloud or hardware)
  - Email OTP (`set email-to ... + set two-factor email`)
  - SMS OTP (`set two-factor sms`)
  - FortiToken Mobile

A hardened FortiGate has `set two-factor <method>` on every super_admin.
Empty / `disable` on any super-admin is a CRITICAL finding for banking
(PCI-DSS 8.4 / SIB Res. 06/2020 art. 15).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_TWO_FACTOR_RE = re.compile(r"^\s*set\s+two-factor\s+(\S+)", re.M)
_PROFILE_RE = re.compile(r'^\s*set\s+accprofile\s+"([^"]+)"', re.M)


class _TwoFactorCheck:
    control_id = "FGT-1.4"
    control_title = "Two-factor authentication enforced on every admin account"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Enable 2FA per admin (FortiToken Mobile is free for first 2 admins):\n"
        "  config system admin\n"
        "    edit <name>\n"
        "      set two-factor fortitoken          # or email / sms\n"
        "      set fortitoken <serial>            # if FortiToken\n"
        "      set email-to admin@empresa.com     # if email\n"
        "    next\n"
        "  end\n"
        "Confirm with: `diagnose fortitoken info` (registered tokens).\n"
        "For PCI-DSS scope, this is non-negotiable on every super_admin."
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

        accounts: list[dict[str, str]] = []
        for m in re.finditer(
            r'edit\s+"([^"]+)"\s*(.*?)\bnext\b',
            out,
            re.S,
        ):
            name = m.group(1)
            body = m.group(2)
            tf_match = _TWO_FACTOR_RE.search(body)
            prof_match = _PROFILE_RE.search(body)
            accounts.append(
                {
                    "name": name,
                    "two_factor": (tf_match.group(1).lower() if tf_match else "disable"),
                    "accprofile": (prof_match.group(1) if prof_match else ""),
                }
            )

        # Only super_admin accprofile matters for the CRITICAL gate. Lower-
        # priv profiles are flagged as HIGH effectively (still in issues).
        issues: list[str] = []
        for a in accounts:
            tf = a["two_factor"]
            if tf in ("", "disable"):
                if a["accprofile"] in ("super_admin", "prof_admin", ""):
                    issues.append(f"admin '{a['name']}' (profile={a['accprofile'] or 'default'}) has 2FA disabled")
                else:
                    issues.append(f"admin '{a['name']}' (profile={a['accprofile']}) lacks 2FA")

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
                "admin_count": len(accounts),
                "admins_without_2fa": [a["name"] for a in accounts if a["two_factor"] in ("", "disable")],
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _TwoFactorCheck()
register_check(CHECK)
