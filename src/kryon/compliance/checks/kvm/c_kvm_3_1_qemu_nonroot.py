"""KVM-3.1 — QEMU processes run as a non-root user.

If /etc/libvirt/qemu.conf sets `user = "root"`, a guest breakout lands with
full host root. QEMU should drop to an unprivileged account (qemu /
libvirt-qemu) so sVirt + non-root contain the blast radius.

FAIL if user is "root" (or "+0"). PASS for a non-root user or the distro
default. ERROR if qemu.conf is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _conf(text: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*"?([^"#\s]+)"?', text, re.MULTILINE)
    return m.group(1) if m else None


class _QemuNonRootCheck:
    control_id = "KVM-3.1"
    control_title = "QEMU processes run as non-root"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Run QEMU unprivileged in /etc/libvirt/qemu.conf:\n"
        '  user = "qemu"     # or "libvirt-qemu" on Debian/Ubuntu\n'
        '  group = "qemu"\n'
        "Restart libvirtd; new/rebooted guests will drop privileges."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        user = _conf(out, "user")
        verdict = "FAIL" if user in ("root", "+0", "0") else "PASS"
        return self._result(verdict, cmd, out, err, {"qemu_user": user or "(default)"}, t0, ctx)

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


CHECK = _QemuNonRootCheck()
register_check(CHECK)
