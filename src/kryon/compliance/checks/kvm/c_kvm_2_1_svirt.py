"""KVM-2.1 — sVirt (SELinux/AppArmor) confinement enabled for guests.

sVirt confines each QEMU process with a MAC label so a guest breakout can't
reach other guests or the host. /etc/libvirt/qemu.conf `security_driver`
must NOT be "none" — it should be "selinux", "apparmor", or left at the
auto-detect default.

FAIL if security_driver is explicitly "none". ERROR if qemu.conf is
unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _conf(text: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*"?([^"#\s]+)"?', text, re.MULTILINE)
    return m.group(1) if m else None


class _SvirtCheck:
    control_id = "KVM-2.1"
    control_title = "sVirt (SELinux/AppArmor) confinement enabled"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Enable MAC confinement in /etc/libvirt/qemu.conf:\n"
        '  security_driver = "selinux"    # or "apparmor"\n'
        "Ensure SELinux is enforcing (or AppArmor loaded); restart libvirtd.\n"
        'Never run production guests with security_driver = "none".'
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        driver = _conf(out, "security_driver")
        verdict = "FAIL" if driver == "none" else "PASS"
        return self._result(verdict, cmd, out, err, {"security_driver": driver or "(default/auto)"}, t0, ctx)

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


CHECK = _SvirtCheck()
register_check(CHECK)
