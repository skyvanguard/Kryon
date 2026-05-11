"""AD-4.1 — SMB signing required on the DC.

Without SMB signing, an attacker on the LAN can relay authenticated
NTLM sessions (responder + ntlmrelayx). Banking perimeter audit treats
unsigned SMB as CRITICAL because DCs always expose SMB.

Probe: `nmap --script smb2-security-mode` against 445/tcp.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SmbSigningCheck:
    control_id = "AD-4.1"
    control_title = "SMB signing required on 445/tcp (mitigates NTLM relay)"
    section = "4"
    severity = "CRITICAL"
    remediation_static = (
        "On DCs (and ideally all servers): Group Policy → Computer → "
        "Windows Settings → Security Settings → Local Policies → "
        "Security Options → 'Microsoft network server: Digitally sign "
        "communications (always)' = Enabled. "
        "Also enable EPA (Extended Protection for Authentication) on "
        "LDAPS and IIS — goes in the same hardening batch."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        _, _, _, dc = ad_env()
        dc = dc or ctx.host

        if not check_tool(ctx, "nmap"):
            return tool_missing_error(
                self.control_id,
                self.control_title,
                self.section,
                self.severity,
                self.remediation_static,
                ctx.host,
                t0,
                tool="nmap",
                install_hint="apt install nmap",
            )

        cmd = f"nmap -Pn -p 445 --script smb2-security-mode {dc} 2>&1 | tail -30"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=25)

        # Output typical:
        #   SMB: Security mode: 3:1
        #   Account used: guest
        #   Authentication level: share
        #   Message signing: required
        message_signing = ""
        for line in out.splitlines():
            if "Message signing" in line or "message signing" in line:
                message_signing = line.split(":", 1)[-1].strip().lower()

        issues: list[str] = []
        parsed = {"nmap_output_tail": out[-800:], "message_signing": message_signing}

        if "required" not in message_signing:
            if message_signing:
                issues.append(f"SMB signing: {message_signing!r} (should be 'required')")
            else:
                issues.append("Could not determine SMB signing state")

        if "closed" in out.lower() or "filtered" in out.lower():
            # 445 filtered = probably good (not exposed) — note but not FAIL
            parsed["note"] = "445/tcp not open from scanner vantage — could be segmentation"

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SmbSigningCheck()
register_check(CHECK)
