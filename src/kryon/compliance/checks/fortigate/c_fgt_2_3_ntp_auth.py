"""FGT-2.3 — NTP authentication enabled.

Without NTP authentication, an attacker on-path can shift system clock,
breaking certificate validation, log correlation, and Kerberos. CIS
recommends signed NTP (`set authentication enable`) or ntp/secure key.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _NtpAuthCheck:
    control_id = "FGT-2.3"
    control_title = "NTP authentication enabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "config system ntp\n"
        "  set type custom\n"
        "  set ntpsync enable\n"
        "  set authentication enable\n"
        "  config ntpserver\n"
        "    edit 1\n"
        "      set server <internal-ntp-or-trusted-public>\n"
        "      set authentication enable\n"
        "      set key-id 1\n"
        "      set key <SHARED-KEY>\n"
        "    next\n"
        "  end\n"
        "end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system ntp"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read ntp config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Top-level authentication directive
        top_auth = re.search(r"^\s*set\s+authentication\s+(\S+)", out, re.M)
        # Per-server authentication
        server_auths: list[bool] = []
        for m in re.finditer(r'edit\s+\d+\s*(.*?)\bnext\b', out, re.S):
            body = m.group(1)
            auth = re.search(r"set\s+authentication\s+(\S+)", body)
            server_auths.append(bool(auth and auth.group(1).lower() == "enable"))

        issues: list[str] = []
        if top_auth and top_auth.group(1).lower() != "enable":
            issues.append("global NTP authentication is disabled")
        if server_auths and not all(server_auths):
            issues.append(
                f"{server_auths.count(False)}/{len(server_auths)} NTP servers without authentication"
            )
        if not top_auth and not server_auths:
            # Default custom block missing, FortiGuard NTP in use → no auth at all
            issues.append("NTP authentication directive not present (default-disabled)")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed={
                "global_authentication": top_auth.group(1).lower() if top_auth else "(absent)",
                "ntp_servers_total": len(server_auths),
                "ntp_servers_authenticated": sum(server_auths),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _NtpAuthCheck()
register_check(CHECK)
