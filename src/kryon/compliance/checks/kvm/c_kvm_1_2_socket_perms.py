"""KVM-1.2 — libvirt local Unix socket access is restricted.

The local RW socket grants full hypervisor control, so it must be limited to
a trusted group — not world-writable. /etc/libvirt/libvirtd.conf sets
`unix_sock_rw_perms` (default "0770") and `unix_sock_group` (e.g. "libvirt").

FAIL if unix_sock_rw_perms grants write to 'other' (world-writable socket).
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


class _SocketPermsCheck:
    control_id = "KVM-1.2"
    control_title = "libvirt local socket access restricted (not world-writable)"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Restrict the RW socket in /etc/libvirt/libvirtd.conf:\n"
        '  unix_sock_group = "libvirt"\n'
        '  unix_sock_rw_perms = "0770"\n'
        "Add trusted admins to the libvirt group; restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/libvirtd.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read libvirtd.conf"}, t0, ctx)

        perms = _conf(out, "unix_sock_rw_perms")
        group = _conf(out, "unix_sock_group")
        world_writable = False
        if perms:
            try:
                world_writable = bool(int(perms[-1]) & 2)  # 'other' write bit
            except ValueError:
                pass

        verdict = "FAIL" if world_writable else "PASS"
        return self._result(verdict, cmd, out, err, {"unix_sock_rw_perms": perms, "unix_sock_group": group}, t0, ctx)

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


CHECK = _SocketPermsCheck()
register_check(CHECK)
