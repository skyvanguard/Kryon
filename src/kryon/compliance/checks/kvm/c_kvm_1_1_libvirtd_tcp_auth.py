"""KVM-1.1 — libvirtd does not expose an unauthenticated TCP socket.

An open libvirt TCP socket (16509) with `auth_tcp = "none"` gives anyone on
the network full control of the hypervisor and every guest — a critical RCE
vector. libvirt should use the local Unix socket, or TLS/SASL if remote
management is required.

FAIL if /etc/libvirt/libvirtd.conf sets `listen_tcp = 1` AND
`auth_tcp = "none"`. ERROR if the config can't be read (not a libvirt host).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _conf(text: str, key: str) -> str | None:
    """Value of an uncommented `key = value` line (quotes stripped)."""
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*"?([^"#\s]+)"?', text, re.MULTILINE)
    return m.group(1) if m else None


class _LibvirtdTcpAuthCheck:
    control_id = "KVM-1.1"
    control_title = "libvirtd has no unauthenticated TCP socket"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Disable the plain TCP listener in /etc/libvirt/libvirtd.conf:\n"
        "  listen_tcp = 0\n"
        "If remote management is required, use TLS with client certs:\n"
        '  listen_tls = 1 ; auth_tcp = "sasl"  (never auth_tcp = "none")\n'
        "Then restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/libvirtd.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read libvirtd.conf"}, t0, ctx)

        listen_tcp = _conf(out, "listen_tcp")
        auth_tcp = _conf(out, "auth_tcp")
        insecure = listen_tcp == "1" and (auth_tcp == "none")

        verdict = "FAIL" if insecure else "PASS"
        return self._result(verdict, cmd, out, err, {"listen_tcp": listen_tcp, "auth_tcp": auth_tcp}, t0, ctx)

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


CHECK = _LibvirtdTcpAuthCheck()
register_check(CHECK)
