"""WIN-3.5 — UAC ConsentPromptBehaviorAdmin set to a strict value (≥ 2)."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _UacCheck:
    control_id = "WIN-3.5"
    control_title = "UAC strict consent prompt for elevation (ConsentPromptBehaviorAdmin ≥ 2)"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Set ConsentPromptBehaviorAdmin to 2 (Prompt for consent on secure desktop)\n"
        "or 5 (Prompt for consent for non-Windows binaries — default):\n"
        "  reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System \\\n"
        "    /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f\n"
        "Or GPO:\n"
        "  Computer Config → Windows Settings → Security Settings →\n"
        "    Local Policies → Security Options → User Account Control:\n"
        "    Behavior of the elevation prompt for administrators in Admin Approval Mode\n"
        "Value 0 = Elevate without prompting (DANGEROUS). 1 = Prompt for credentials."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "(Get-ItemProperty '
            "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            '-Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ItemNotFound" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        try:
            n = int(value) if value else 5  # default = 5 in modern Windows
        except ValueError:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason=f"non-numeric: {value!r}")

        verdict = "PASS" if n >= 2 else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"ConsentPromptBehaviorAdmin": n},
            t0=t0,
            ctx=ctx,
        )


CHECK = _UacCheck()
register_check(CHECK)
