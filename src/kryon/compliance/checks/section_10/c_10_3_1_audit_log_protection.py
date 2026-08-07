"""PCI-DSS v4 control 10.3.1 — Read access to audit log files is limited to
those with a job-related need.

Audit logs must not be world-readable and must be owned by root. Checks the
permissions of /var/log/audit/audit.log via `stat`.

PASS if not world-readable AND owned by root. FAIL otherwise. N/A if the
audit log doesn't exist (auditd not installed — that gap is 10.2.1's job).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_AUDIT_LOG = "/var/log/audit/audit.log"


class _C1031Check:
    control_id = "10.3.1"
    control_title = "Audit log access restricted"
    section = "10"
    severity = "MEDIUM"
    remediation_static = (
        "Restrict the audit logs: `chown root:root /var/log/audit/audit.log` and "
        "`chmod 600 /var/log/audit/audit.log`. Set `log_group = root` and "
        "`log_file_mode = 0600` in /etc/audit/auditd.conf so rotation keeps the "
        "permissions tight (PCI-DSS 10.3.1)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, ["stat", "-c", "%a %U %G", _AUDIT_LOG], timeout_s=4)
        if rc != 0 or not out.strip():
            return self._result("N/A", out, err, {"reason": f"{_AUDIT_LOG} not present"}, t0, ctx)

        parts = out.split()
        mode = parts[0] if parts else ""
        owner = parts[1] if len(parts) > 1 else ""

        world_readable = False
        try:
            world_readable = bool(int(mode[-1]) & 4)  # 'other' read bit
        except (ValueError, IndexError):
            pass

        issues: list[str] = []
        if world_readable:
            issues.append(f"world-readable (mode {mode})")
        if owner and owner != "root":
            issues.append(f"owner is {owner}, not root")

        return self._result(
            "FAIL" if issues else "PASS",
            out,
            err,
            {"mode": mode, "owner": owner, "world_readable": world_readable, "issues": sorted(issues)},
            t0,
            ctx,
        )

    def _result(self, verdict, stdout, stderr, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"stat -c '%a %U %G' {_AUDIT_LOG}",
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C1031Check()
register_check(CHECK)
