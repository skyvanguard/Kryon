"""KVM-1.3 — libvirt audit logging enabled.

libvirt can emit records to the Linux audit subsystem (VM lifecycle, resource
assignment, security-label changes) — evidence needed for incident response
and compliance. /etc/libvirt/libvirtd.conf `audit_level` controls it:
0 = disabled, 1 = enabled if the host audit daemon is present, 2 = required.

FAIL if audit_level is explicitly 0. PASS if >= 1 or left at the default.
ERROR if the config can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _conf(text: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*"?([^"#\s]+)"?', text, re.MULTILINE)
    return m.group(1) if m else None


class _AuditLoggingCheck:
    control_id = "KVM-1.3"
    control_title = "libvirt audit logging enabled"
    section = "1"
    severity = "LOW"
    remediation_static = (
        "Enable libvirt auditing in /etc/libvirt/libvirtd.conf:\n"
        "  audit_level = 1        # or 2 to require the audit subsystem\n"
        "  audit_logging = 1\n"
        "Ensure auditd is running; restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/libvirtd.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read libvirtd.conf"}, t0, ctx)

        value = _conf(out, "audit_level")
        verdict = "FAIL" if value == "0" else "PASS"
        return self._result(verdict, cmd, out, err, {"audit_level": value or "(default enabled)"}, t0, ctx)

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AuditLoggingCheck()
register_check(CHECK)
