"""FGT-1.3 — Admin accounts restricted by `trusthost` source IPs.

Without `trusthost`, an admin can log in from anywhere the management port
is reachable. FortiGate management portals exposed to the Internet have
been mass-exploited (CVE-2022-42475 etc.) — `trusthost` is the cheapest
mitigation.

A correctly hardened account has trusthost1..trusthostN set to specific
admin subnets. Wildcard `0.0.0.0 0.0.0.0` (== any) counts as missing.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_TRUSTHOST_LINE = re.compile(
    r"^\s*set\s+trusthost\d+\s+(\S+)\s+(\S+)\s*$",
    re.M,
)


class _TrusthostCheck:
    control_id = "FGT-1.3"
    control_title = "Admin accounts restrict source IPs via trusthost"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Restrict each admin to your management subnet:\n"
        "  config system admin\n"
        "    edit <name>\n"
        "      set trusthost1 10.10.0.0 255.255.0.0\n"
        "      set trusthost2 192.0.2.10 255.255.255.255   # jump host\n"
        "    next\n"
        "  end\n"
        "Avoid trusthost = 0.0.0.0 0.0.0.0 (== any source). For SSL VPN\n"
        "users that need GUI access, use a dedicated low-priv admin profile."
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

        accounts: list[dict[str, object]] = []
        for m in re.finditer(
            r'edit\s+"([^"]+)"\s*(.*?)\bnext\b',
            out,
            re.S,
        ):
            name = m.group(1)
            body = m.group(2)
            trusthosts: list[tuple[str, str]] = []
            for th in _TRUSTHOST_LINE.finditer(body):
                trusthosts.append((th.group(1), th.group(2)))
            accounts.append({"name": name, "trusthosts": trusthosts})

        issues: list[str] = []
        for acct in accounts:
            ths: list[tuple[str, str]] = acct["trusthosts"]  # type: ignore[assignment]
            if not ths:
                issues.append(f"admin '{acct['name']}' has no trusthost (any source allowed)")
                continue
            # Any wildcard entry effectively defeats the others
            for ip, mask in ths:
                if ip == "0.0.0.0" and mask == "0.0.0.0":
                    issues.append(f"admin '{acct['name']}' has trusthost=0.0.0.0/0 (== any)")
                    break

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
                "accounts_without_trusthost": [
                    a["name"]
                    for a in accounts
                    if not a["trusthosts"]  # type: ignore[index]
                ],
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _TrusthostCheck()
register_check(CHECK)
