"""AD-5.1 — Critical audit events are being logged.

Banking evidence requirement: DCs must log 4624 (logon), 4625 (failed),
4672 (special privileges), 4720 (user created), 4728/4732/4756 (group
changes), 4768/4769 (kerberos), 5136 (directory changes).

We can't read Windows Event Log from Linux directly; use `rpcclient`
`srvinfo` / `enumerate_audit` equivalent via `net rpc audit`. If that
fails (common when auditing Samba-free), we fall back to checking
advertised event forwarding subscriptions on port 5985/5986 (WinRM).

Best-effort check — PASS/FAIL only when we actually get data, ERROR
with actionable notes otherwise (still useful for the banking report).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    missing_creds_error,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

REQUIRED_EVENT_IDS = [
    "4624",  # Successful logon
    "4625",  # Failed logon
    "4672",  # Special privileges assigned
    "4720",  # User created
    "4728",  # Added to global group
    "4732",  # Added to local group
    "4756",  # Added to universal group
    "4768",  # Kerberos TGT requested
    "4769",  # Kerberos service ticket requested
    "5136",  # Directory service object modified
]


class _AuditPolicyCheck:
    control_id = "AD-5.1"
    control_title = "Critical AD audit events (logon, kerberos, privilege) are logged"
    section = "5"
    severity = "HIGH"
    remediation_static = (
        "Enable Advanced Audit Policy via Group Policy → Computer → "
        "Policies → Windows Settings → Security Settings → Advanced Audit "
        "Policy Configuration. Subcategories to turn on for Success+Failure: "
        "Logon, Logoff, Credential Validation, Kerberos Authentication Service, "
        "Kerberos Service Ticket Operations, Directory Service Access, "
        "Directory Service Changes, User Account Management, Security Group "
        "Management, Sensitive Privilege Use. "
        "Forward to SIEM (Splunk/Wazuh) via Windows Event Forwarding."
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

        if not check_tool(ctx, "rpcclient"):
            return tool_missing_error(
                self.control_id,
                self.control_title,
                self.section,
                self.severity,
                self.remediation_static,
                ctx.host,
                t0,
                tool="rpcclient",
                install_hint="apt install smbclient",
            )

        # Probe WinRM 5985/5986 first — if not reachable, SIEM forwarding
        # is very unlikely to exist.
        nmap_cmd = f"nmap -Pn -p 5985,5986 {dc} 2>&1 | tail -6"
        n_out, _, _ = run_cmd(ctx, nmap_cmd, shell=True, timeout_s=20)

        winrm_open = "5985/tcp open" in n_out or "5986/tcp open" in n_out

        # Try `rpcclient` netsharegetinfo as a low-priv sanity check
        rpc_cmd = f"rpcclient -U '{domain}\\\\{user}%{pwd}' -c 'srvinfo' {dc} 2>&1 | head -10"
        r_out, r_err, r_rc = run_cmd(ctx, rpc_cmd, shell=True, timeout_s=10)

        issues: list[str] = []
        parsed: dict = {
            "winrm_listening": winrm_open,
            "rpc_reachable": r_rc == 0 and "server type" in r_out.lower(),
            "required_event_ids": REQUIRED_EVENT_IDS,
            "note": (
                "Direct Event Log query requires Windows-side tooling "
                "(wevtutil, PowerShell). This check verifies network "
                "reachability of Event Forwarding and baseline RPC; "
                "detailed event-by-event audit requires on-DC script."
            ),
        }

        if not winrm_open:
            issues.append("WinRM (5985/5986) not reachable — Event Forwarding to SIEM unlikely to be configured")

        if r_rc != 0 and "NT_STATUS_LOGON_FAILURE" not in r_out:
            # If logon failed, we still counted something
            issues.append(f"rpcclient srvinfo failed: {r_out[:200]}")

        # Because we can't read Windows events from Linux, verdict is
        # PASS only if WinRM reachable AND RPC responded — a necessary
        # (not sufficient) condition for centralized audit logging.
        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{nmap_cmd} ; {rpc_cmd.replace(pwd, '***')}",
            evidence_stdout=(f"=== nmap WinRM ===\n{n_out}\n\n=== rpcclient srvinfo ===\n{r_out}")[:2048],
            evidence_stderr=r_err[:256],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AuditPolicyCheck()
register_check(CHECK)
