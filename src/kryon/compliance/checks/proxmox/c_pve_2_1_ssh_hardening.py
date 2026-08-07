"""PVE-2.1 — SSH hardening on Proxmox node.

Proxmox defaults allow root + password auth for bootstrap, but in a
banking production environment:
  - PermitRootLogin = no   (use sudo/su from admin account)
  - PasswordAuthentication = no   (key-only)
  - Protocol 2 only  (default in OpenSSH 7+)
  - ClientAliveInterval <= 300, ClientAliveCountMax >= 0

CIS Proxmox / CIS Debian benchmarks require these. Misconfig here is
the #1 finding across every banking pentest we run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SshHardeningCheck:
    control_id = "PVE-2.1"
    control_title = "SSH allows only key-based, non-root authentication"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Edit /etc/ssh/sshd_config and set:\n"
        "  PermitRootLogin no\n"
        "  PasswordAuthentication no\n"
        "  PubkeyAuthentication yes\n"
        "  ClientAliveInterval 300\n"
        "  ClientAliveCountMax 2\n"
        "Then: systemctl restart ssh. "
        "Validate a separate sudo-enabled account works BEFORE restarting."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "sshd -T 2>/dev/null || cat /etc/ssh/sshd_config"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=6)

        if rc not in (0, 1) and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read sshd config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        def directive(name: str) -> str:
            # sshd -T emits lowercase directives; sshd_config mixed case.
            m = re.search(rf"^\s*{name}\s+(\S+)", out, re.M | re.I)
            return m.group(1).strip().lower() if m else ""

        permit_root = directive("PermitRootLogin")
        pwd_auth = directive("PasswordAuthentication")
        pubkey_auth = directive("PubkeyAuthentication")
        keep_alive = directive("ClientAliveInterval")

        issues: list[str] = []
        if permit_root and permit_root not in ("no", "prohibit-password"):
            issues.append(f"PermitRootLogin={permit_root} (should be no)")
        if pwd_auth and pwd_auth != "no":
            issues.append(f"PasswordAuthentication={pwd_auth} (should be no)")
        if pubkey_auth and pubkey_auth not in ("yes", ""):
            issues.append(f"PubkeyAuthentication={pubkey_auth} (should be yes)")
        if keep_alive:
            try:
                if int(keep_alive) > 600 or int(keep_alive) == 0:
                    issues.append(f"ClientAliveInterval={keep_alive} (<=600 recommended)")
            except ValueError:
                pass

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
                "PermitRootLogin": permit_root,
                "PasswordAuthentication": pwd_auth,
                "PubkeyAuthentication": pubkey_auth,
                "ClientAliveInterval": keep_alive,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SshHardeningCheck()
register_check(CHECK)
