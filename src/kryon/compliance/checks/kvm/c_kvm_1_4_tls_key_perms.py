"""KVM-1.4 — libvirt TLS server private key is protected.

If libvirt is configured for TLS remote management, the server private key
(/etc/pki/libvirt/private/serverkey.pem) must be readable only by root —
group/world read exposes the key and lets an attacker impersonate the
hypervisor. Checked via `stat`.

FAIL if the key is group- or world-readable, or not root-owned. N/A if the
key is absent (no TLS configured — KVM-1.1 covers the plain-socket case).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_KEY = "/etc/pki/libvirt/private/serverkey.pem"


class _TlsKeyPermsCheck:
    control_id = "KVM-1.4"
    control_title = "libvirt TLS server private key protected"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        f"Lock down the TLS server key:\n  chown root:root {_KEY} && chmod 0600 {_KEY}\n"
        "Same for /etc/pki/CA/cakey.pem. Never leave private keys group/world readable."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = f"stat -c '%a %U' {_KEY} 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=6)
        if rc != 0 or not out.strip():
            return self._result("N/A", cmd, out, err, {"reason": "no TLS server key (TLS not configured)"}, t0, ctx)

        parts = out.split()
        mode = parts[0] if parts else ""
        owner = parts[1] if len(parts) > 1 else ""

        issues: list[str] = []
        try:
            group_bits = int(mode[-2])
            other_bits = int(mode[-1])
            if group_bits != 0:
                issues.append(f"group access (mode {mode})")
            if other_bits != 0:
                issues.append(f"world access (mode {mode})")
        except (ValueError, IndexError):
            pass
        if owner and owner != "root":
            issues.append(f"owner {owner} != root")

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


CHECK = _TlsKeyPermsCheck()
register_check(CHECK)
