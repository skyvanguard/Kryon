"""KVM-3.6 — cgroup device ACL does not expose dangerous host devices.

/etc/libvirt/qemu.conf `cgroup_device_acl` whitelists the host device nodes
QEMU may open. libvirt's built-in default is a safe set (/dev/null, /dev/kvm,
…). If an operator widens it to include raw memory or block devices
(/dev/mem, /dev/kmem, /dev/port, /dev/sd*, /dev/nvme*, /dev/vd*), a guest can
read host RAM or other VMs' disks.

FAIL if an uncommented cgroup_device_acl lists a dangerous device. PASS if
unset (safe default) or only safe devices. ERROR if qemu.conf is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_ACL_RE = re.compile(r"^\s*cgroup_device_acl\s*=\s*\[(.*?)\]", re.MULTILINE | re.DOTALL)
_DANGEROUS = ("/dev/mem", "/dev/kmem", "/dev/port", "/dev/sd", "/dev/nvme", "/dev/vd", "/dev/dm-")


class _DeviceAclCheck:
    control_id = "KVM-3.6"
    control_title = "cgroup device ACL exposes no dangerous host devices"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Remove raw memory/disk nodes from cgroup_device_acl in "
        "/etc/libvirt/qemu.conf — leave it at the libvirt default, or list only\n"
        "safe pseudo-devices (/dev/null, /dev/full, /dev/zero, /dev/random,\n"
        "/dev/urandom, /dev/ptmx, /dev/kvm). Never expose /dev/mem or raw disks."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        m = _ACL_RE.search(out)
        if not m:
            return self._result("PASS", cmd, out, err, {"cgroup_device_acl": "(default safe set)"}, t0, ctx)

        # Ignore commented lines inside the block.
        acl = "\n".join(ln for ln in m.group(1).splitlines() if not ln.strip().startswith("#"))
        found = sorted({d for d in _DANGEROUS if d in acl})
        verdict = "FAIL" if found else "PASS"
        return self._result(verdict, cmd, out, err, {"dangerous_devices": found}, t0, ctx)

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


CHECK = _DeviceAclCheck()
register_check(CHECK)
