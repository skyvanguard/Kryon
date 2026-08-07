"""KVM-3.4 — QEMU drops extra Linux capabilities.

/etc/libvirt/qemu.conf `clear_emulator_capabilities = 1` (the default) makes
libvirt strip QEMU down to only the capabilities it needs, so a compromised
emulator can't wield host privileges like CAP_SYS_ADMIN. Setting it to 0
leaves QEMU over-privileged.

FAIL if clear_emulator_capabilities is explicitly 0. PASS if 1 or default.
ERROR if qemu.conf is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _conf(text: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*"?([^"#\s]+)"?', text, re.MULTILINE)
    return m.group(1) if m else None


class _ClearCapabilitiesCheck:
    control_id = "KVM-3.4"
    control_title = "QEMU drops extra Linux capabilities"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Strip QEMU capabilities in /etc/libvirt/qemu.conf:\n"
        "  clear_emulator_capabilities = 1\n"
        "Restart libvirtd; reboot guests to apply."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        value = _conf(out, "clear_emulator_capabilities")
        verdict = "FAIL" if value == "0" else "PASS"
        return self._result(
            verdict, cmd, out, err, {"clear_emulator_capabilities": value or "(default enabled)"}, t0, ctx
        )

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


CHECK = _ClearCapabilitiesCheck()
register_check(CHECK)
