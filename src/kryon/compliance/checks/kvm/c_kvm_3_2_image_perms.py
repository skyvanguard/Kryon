"""KVM-3.2 — VM disk-image storage is not world-accessible.

/var/lib/libvirt/images holds guest disks (often with credentials/data at
rest). A world-writable directory lets any local user tamper with or plant
disk images; world-readable leaks guest data. Checked via `stat`.

FAIL if the images directory is world-writable (or world-readable). ERROR
if it can't be stat'd (path may differ — surfaced for manual review).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_IMAGES_DIR = "/var/lib/libvirt/images"


class _ImagePermsCheck:
    control_id = "KVM-3.2"
    control_title = "VM image storage not world-accessible"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Restrict the image store:\n"
        f"  chown root:libvirt {_IMAGES_DIR} && chmod 0750 {_IMAGES_DIR}\n"
        "Ensure individual images are 0600 root/qemu. Encrypt at rest where required."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = f"stat -c '%a %U %G' {_IMAGES_DIR} 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=6)
        if rc != 0 or not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": f"{_IMAGES_DIR} not found / unreadable"}, t0, ctx)

        parts = out.split()
        mode = parts[0] if parts else ""
        owner = parts[1] if len(parts) > 1 else ""
        world_write = False
        world_read = False
        try:
            other = int(mode[-1])
            world_write = bool(other & 2)
            world_read = bool(other & 4)
        except (ValueError, IndexError):
            pass

        issues: list[str] = []
        if world_write:
            issues.append(f"world-writable (mode {mode})")
        if world_read:
            issues.append(f"world-readable (mode {mode})")

        verdict = "FAIL" if issues else "PASS"
        return self._result(verdict, cmd, out, err, {"mode": mode, "owner": owner, "issues": issues}, t0, ctx)

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


CHECK = _ImagePermsCheck()
register_check(CHECK)
