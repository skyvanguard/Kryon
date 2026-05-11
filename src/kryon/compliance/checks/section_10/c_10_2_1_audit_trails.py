"""PCI-DSS v4 control 10.2.1 — Audit trails.

Two sub-checks, verdict FAIL if either fails:
  A) auditd service is active (systemctl is-active auditd).
  B) /etc/audit/rules.d/ contains at least the PCI minimum watchers:
     - `-w /etc/passwd` (identity changes)
     - `-w /etc/shadow` (credential changes)
     - `-w /etc/sudoers` (privilege changes)
     - `-a always,exit -F arch=b64 -S execve` or equivalent (command audit)

Evidence: `systemctl is-active auditd` + concatenation of rules.d/*.rules.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_REQUIRED_WATCHES = (
    r"-w\s+/etc/passwd",
    r"-w\s+/etc/shadow",
    r"-w\s+/etc/sudoers",
)
_EXECVE_RULE = re.compile(r"-a\s+(always,exit|exit,always).*-S\s+execve")


class _C1021Check:
    control_id = "10.2.1"
    control_title = "Audit trails"
    section = "10"
    severity = "HIGH"
    remediation_static = (
        "Install and enable auditd (`apt install auditd`, `systemctl enable --now auditd`). "
        "Add PCI minimum rules to /etc/audit/rules.d/pci.rules: watches on "
        "/etc/passwd, /etc/shadow, /etc/sudoers (use `-w <file> -p wa -k identity`) "
        "and execve tracking (`-a always,exit -F arch=b64 -S execve -k exec`). "
        "Reload rules: `augenrules --load`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()

        active_out, active_err, active_rc = run_cmd(
            ctx, ["systemctl", "is-active", "auditd"], timeout_s=4,
        )
        auditd_active = active_out.strip() == "active"

        rules_out, rules_err, rules_rc = run_cmd(
            ctx, ["sh", "-c",
                  "cat /etc/audit/rules.d/*.rules 2>/dev/null; "
                  "cat /etc/audit/audit.rules 2>/dev/null"],
            timeout_s=5,
        )

        missing_watches = []
        for pattern in _REQUIRED_WATCHES:
            if not re.search(pattern, rules_out):
                missing_watches.append(pattern.replace(r"\s+", " ").replace(r"-w ", "-w "))

        execve_present = bool(_EXECVE_RULE.search(rules_out))

        issues: list[str] = []
        if not auditd_active:
            issues.append(f"auditd service: {active_out.strip() or 'unavailable'}")
        if missing_watches:
            issues.append(f"missing file watches: {missing_watches}")
        if not execve_present:
            issues.append("no execve audit rule (command-exec tracking)")

        # Handle ERROR: if systemctl not present, we can't assert service state.
        if active_rc != 0 and not active_out.strip():
            # systemctl returned but empty → either init is not systemd, or
            # service genuinely not installed. We distinguish by checking
            # whether ANY rules file exists.
            if not rules_out.strip():
                return CheckResult(
                    control_id=self.control_id,
                    control_title=self.control_title,
                    section=self.section,
                    verdict="FAIL",
                    evidence_command="systemctl is-active auditd ; cat /etc/audit/rules.d/*.rules",
                    evidence_stdout="auditd not installed or non-systemd init",
                    evidence_stderr=(active_err + rules_err)[:1024],
                    evidence_parsed={
                        "auditd_active": False,
                        "rules_found": False,
                        "issues": ["auditd not installed"],
                    },
                    remediation_static=self.remediation_static,
                    severity=self.severity,
                    duration_ms=int((time.time() - t0) * 1000),
                    host=ctx.host,
                    run_id="",
                )

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="systemctl is-active auditd ; cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules",
            evidence_stdout=(
                f"=== auditd service ===\n{active_out}\n"
                f"=== audit rules (first 3KB) ===\n{rules_out[:3000]}"
            )[:4096],
            evidence_stderr=(active_err + "\n" + rules_err)[:1024],
            evidence_parsed={
                "auditd_active": auditd_active,
                "required_watches_present": sorted([
                    p.replace(r"\s+", " ") for p in _REQUIRED_WATCHES
                    if re.search(p, rules_out)
                ]),
                "required_watches_missing": sorted(missing_watches),
                "execve_rule_present": execve_present,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C1021Check()
register_check(CHECK)
