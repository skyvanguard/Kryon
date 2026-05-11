"""AD-2.2 — krbtgt password rotated within last 180 days.

The krbtgt account signs all Kerberos TGTs. If an attacker dumps its
hash, they can forge Golden Tickets good for 10+ years — standard
banking incident scenario. Microsoft recommends rotating krbtgt twice
every 180 days.

We read `pwdLastSet` from the krbtgt user and compute age.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    missing_creds_error,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# Windows FILETIME epoch (1601-01-01) to Unix conversion constants
WIN_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class _KrbtgtRotationCheck:
    control_id = "AD-2.2"
    control_title = "krbtgt password rotated within last 180 days"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Use the Microsoft `New-KrbtgtKeys.ps1` script to rotate. "
        "Run it TWICE with 10h between runs to invalidate all cached "
        "tickets. Schedule semi-annually. "
        "Validate: Get-ADUser krbtgt -Properties PasswordLastSet, "
        "msDS-KeyVersionNumber. KVN should increment."
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
        cmd = (
            f"ldapsearch -x -H ldap://{dc} -D '{user}' -w '{pwd}' "
            f"-b '{base_dn}' "
            f"'(sAMAccountName=krbtgt)' "
            f"pwdLastSet msDS-KeyVersionNumber 2>&1"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        pwd_last = _grab(r"^pwdLastSet:\s*(\d+)$", out)
        kvn = _grab(r"^msDS-KeyVersionNumber:\s*(\d+)$", out)

        if not pwd_last:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd.replace(pwd, "***"),
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "krbtgt pwdLastSet not returned", "rc": rc},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Windows FILETIME to Unix
        ft = int(pwd_last)
        last_changed = WIN_EPOCH + timedelta(microseconds=ft // 10)
        age_days = (datetime.now(timezone.utc) - last_changed).days

        issues: list[str] = []
        parsed = {
            "pwdLastSet_raw": pwd_last,
            "last_changed_utc": last_changed.isoformat(),
            "age_days": age_days,
            "kvn": kvn or "?",
        }

        if age_days > 180:
            issues.append(f"krbtgt password is {age_days} days old (>180)")

        if kvn and int(kvn) < 3:
            issues.append(f"msDS-KeyVersionNumber={kvn} (expect >=3 after 2 rotations)")

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd.replace(pwd, "***"),
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def _grab(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.M)
    return m.group(1).strip() if m else None


CHECK = _KrbtgtRotationCheck()
register_check(CHECK)
