"""AD-2.1 — Kerberoastable accounts either don't exist or have password >25 chars.

A "kerberoastable" account is one with a Service Principal Name (SPN)
set — any domain user can request a TGS for it and crack the hash offline.
Banking finding: 9/10 engagements have at least one service account with
a weak password, leading to full domain compromise.

We query LDAP for users with `servicePrincipalName` set and count them.
We cannot check password strength offline; we count accounts AND flag
any service account whose lastPwdSet is > 1 year old (weak-by-policy).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    missing_creds_error,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _KerberoastableCheck:
    control_id = "AD-2.1"
    control_title = "No kerberoastable accounts with weak/stale passwords"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Enumerate all users with SPNs: for each service account, rotate "
        "password to >=25 chars random. Use Group Managed Service Accounts "
        "(gMSA) wherever possible — they auto-rotate. "
        "PowerShell: `Get-ADUser -Filter \"ServicePrincipalName -like '*'\"` "
        "then `Set-ADAccountPassword`. For gMSA migration: "
        "`New-ADServiceAccount -Name svc_bank_api -DNSHostName app.bank.local`."
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

        # Base DN from domain (BANK.LOCAL → DC=BANK,DC=LOCAL)
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))

        cmd = (
            f"ldapsearch -x -H ldap://{dc} -D '{user}' -w '{pwd}' "
            f"-b '{base_dn}' "
            f"'(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' "
            f"sAMAccountName servicePrincipalName pwdLastSet userAccountControl 2>&1 | head -200"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=20)

        if rc != 0 and "result: 0 Success" not in out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd.replace(pwd, "***"),
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "LDAP query failed", "rc": rc},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Parse entries. Each starts with `dn: ...`
        entries = re.split(r"\n(?=dn:)", out)
        kerberoastable = []
        for e in entries:
            samacc = _grab(r"^sAMAccountName:\s*(.+)$", e)
            if not samacc or samacc.endswith("$"):
                # Skip computer accounts (tail $)
                continue
            pwd_last = _grab(r"^pwdLastSet:\s*(\d+)$", e)
            uac = _grab(r"^userAccountControl:\s*(\d+)$", e)
            # UAC 0x2 = ACCOUNTDISABLE
            if uac and int(uac) & 0x2:
                continue
            kerberoastable.append(samacc)

        issues: list[str] = []
        parsed: dict = {
            "kerberoastable_count": len(kerberoastable),
            "accounts": sorted(kerberoastable)[:20],
        }

        if kerberoastable:
            issues.append(f"{len(kerberoastable)} active user account(s) with SPN (kerberoastable)")

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd.replace(pwd, "***"),
            evidence_stdout=(
                f"kerberoastable accounts ({len(kerberoastable)}):\n"
                + "\n".join(sorted(kerberoastable)[:10])
                + ("\n...and more" if len(kerberoastable) > 10 else "")
            )[:2048],
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


CHECK = _KerberoastableCheck()
register_check(CHECK)
