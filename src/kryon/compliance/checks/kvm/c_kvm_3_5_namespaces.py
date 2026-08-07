"""KVM-3.5 — QEMU runs in a private mount namespace.

/etc/libvirt/qemu.conf `namespaces = [ "mount" ]` (the modern default) runs
each QEMU in its own mount namespace, so a compromised guest can't see or
tamper with the host's /dev, /proc or other mounts. An explicitly empty
list disables that isolation.

FAIL if namespaces is set to an empty list (isolation disabled). PASS if it
contains "mount" or is left at the default. ERROR if qemu.conf is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_LIST_RE = re.compile(r"^\s*namespaces\s*=\s*\[(.*?)\]", re.MULTILINE | re.DOTALL)


class _NamespacesCheck:
    control_id = "KVM-3.5"
    control_title = "QEMU runs in a private mount namespace"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Keep mount-namespace isolation in /etc/libvirt/qemu.conf:\n"
        '  namespaces = [ "mount" ]\n'
        "Do not set namespaces = [ ] in production; restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        m = _LIST_RE.search(out)
        if not m:
            # Not set -> libvirt default includes "mount".
            return self._result("PASS", cmd, out, err, {"namespaces": "(default: mount)"}, t0, ctx)

        content = m.group(1)
        has_mount = "mount" in content
        verdict = "PASS" if has_mount else "FAIL"
        return self._result(verdict, cmd, out, err, {"namespaces_has_mount": has_mount}, t0, ctx)

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


CHECK = _NamespacesCheck()
register_check(CHECK)
