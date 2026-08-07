"""KVM-1.5 — libvirt TLS client-certificate verification is enabled.

When libvirt listens over TLS, `tls_no_verify_certificate = 1` in
/etc/libvirt/libvirtd.conf disables client-certificate checking — anyone who
can reach the TLS port (16514) gets full hypervisor control, defeating the
point of mTLS. Verification must stay on.

FAIL if tls_no_verify_certificate = 1. PASS if 0 / unset (verification on).
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


class _TlsVerifyCheck:
    control_id = "KVM-1.5"
    control_title = "libvirt TLS client-certificate verification enabled"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Keep client-cert verification on in /etc/libvirt/libvirtd.conf:\n"
        "  tls_no_verify_certificate = 0\n"
        "Distribute per-client certs signed by your CA; restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/libvirtd.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read libvirtd.conf"}, t0, ctx)

        value = _conf(out, "tls_no_verify_certificate")
        verdict = "FAIL" if value == "1" else "PASS"
        return self._result(verdict, cmd, out, err, {"tls_no_verify_certificate": value or "(default 0)"}, t0, ctx)

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


CHECK = _TlsVerifyCheck()
register_check(CHECK)
