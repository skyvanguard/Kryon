"""PVE-2.4 — Kernel security sysctl hardening.

Baseline kernel hardening that is safe on a hypervisor (does NOT touch
networking/forwarding the host needs):
  kernel.kptr_restrict     >= 1   (hide kernel pointers from unprivileged)
  kernel.dmesg_restrict     = 1   (restrict dmesg to privileged)
  fs.protected_hardlinks    = 1   (mitigate hardlink TOCTOU)
  fs.protected_symlinks     = 1   (mitigate symlink attacks)

FAIL if any of these is below its secure value. ERROR if sysctl can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# key -> minimum acceptable integer value
_EXPECTED = {
    "kernel.kptr_restrict": 1,
    "kernel.dmesg_restrict": 1,
    "fs.protected_hardlinks": 1,
    "fs.protected_symlinks": 1,
}


def _val(out: str, key: str) -> int | None:
    m = re.search(rf"^{re.escape(key)}\s*=\s*(-?\d+)", out, re.M)
    return int(m.group(1)) if m else None


class _KernelSysctlCheck:
    control_id = "PVE-2.4"
    control_title = "Kernel security sysctl hardening"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Harden the kernel in /etc/sysctl.d/99-pve-hardening.conf:\n"
        "  kernel.kptr_restrict = 2\n"
        "  kernel.dmesg_restrict = 1\n"
        "  fs.protected_hardlinks = 1\n"
        "  fs.protected_symlinks = 1\n"
        "Apply with `sysctl --system`. (Safe on a hypervisor — no forwarding impact.)"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        keys = " ".join(_EXPECTED)
        cmd = f"sysctl {keys} 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read sysctl values"}, t0, ctx)

        values: dict[str, int | None] = {}
        issues: list[str] = []
        for key, minimum in _EXPECTED.items():
            v = _val(out, key)
            values[key] = v
            if v is None or v < minimum:
                issues.append(f"{key}={v if v is not None else '(unset)'} (< {minimum})")

        verdict = "PASS" if not issues else "FAIL"
        return self._result(verdict, cmd, out, err, {"values": values, "issues": sorted(issues)}, t0, ctx)

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


CHECK = _KernelSysctlCheck()
register_check(CHECK)
