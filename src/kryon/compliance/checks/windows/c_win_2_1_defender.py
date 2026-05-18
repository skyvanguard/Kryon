"""WIN-2.1 — Microsoft Defender real-time protection enabled."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _DefenderCheck:
    control_id = "WIN-2.1"
    control_title = "Microsoft Defender real-time protection enabled"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Enable Defender RTP:\n"
        "  Set-MpPreference -DisableRealtimeMonitoring $false\n"
        "Also ensure tamper protection is on (cloud-managed):\n"
        "  Set-MpPreference -DisableTamperProtection $false (via Intune/SCCM)\n"
        "If a third-party AV is installed and registered with WSC, this\n"
        "check may legitimately PASS even with Defender RTP off — Defender\n"
        "yields to the third-party. In that case, verify the third-party\n"
        "AV is itself active. The reverse (no AV, Defender off) is the\n"
        "real risk this check catches."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "'
            "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue;"
            'if ($s) { Write-Output ("RTP=$($s.RealTimeProtectionEnabled) ServiceEnabled=$($s.AntivirusEnabled)") } '
            "else { Write-Output 'NO_MPSTATUS' }\""
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        text = out.strip()
        if text == "NO_MPSTATUS":
            # Defender service not available — could be Server SKU without
            # Defender (older Win Server 2016 default) or it's been ripped
            # out. Flag as FAIL with a clear reason.
            return make_result(
                check=self,
                verdict="FAIL",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"reason": "Get-MpComputerStatus not available — Defender absent or disabled"},
                t0=t0,
                ctx=ctx,
            )

        rtp_on = "RTP=True" in text
        verdict = "PASS" if rtp_on else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"realtime_protection_enabled": rtp_on, "raw": text},
            t0=t0,
            ctx=ctx,
        )


CHECK = _DefenderCheck()
register_check(CHECK)
