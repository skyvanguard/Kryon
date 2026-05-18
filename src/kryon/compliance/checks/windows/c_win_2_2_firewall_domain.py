"""WIN-2.2 — Windows Firewall enabled on Domain profile."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _FirewallDomainCheck:
    control_id = "WIN-2.2"
    control_title = "Windows Firewall enabled on Domain profile"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Enable the firewall for all three profiles:\n"
        "  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\n"
        "Or via GPO:\n"
        "  Computer Config → Windows Settings → Security Settings →\n"
        "    Windows Defender Firewall with Advanced Security →\n"
        "    Domain Profile: State=On (recommended)\n"
        "If a third-party firewall is in use, the Windows Firewall service\n"
        "may stop on its own — confirm the third-party covers the same\n"
        "policy boundary."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = 'powershell -nop -c "(Get-NetFirewallProfile -Profile Domain).Enabled"'
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip().lower()
        if value.endswith("true"):
            verdict, parsed = "PASS", {"domain_profile_enabled": True}
        elif value.endswith("false"):
            verdict, parsed = "FAIL", {"domain_profile_enabled": False}
        else:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason=f"unparseable output: {value!r}")
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _FirewallDomainCheck()
register_check(CHECK)
