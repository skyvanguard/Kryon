"""KVM-2.2 — VNC guest consoles are not exposed unauthenticated.

QEMU VNC consoles give full keyboard/screen access to a guest. /etc/libvirt/
qemu.conf `vnc_listen` should bind to localhost (127.0.0.1) so consoles are
only reachable through an authenticated libvirt/SSH tunnel; if bound to
0.0.0.0 it must at least require TLS or SASL.

FAIL if vnc_listen = "0.0.0.0" AND neither vnc_tls=1 nor vnc_sasl=1.
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


class _VncExposureCheck:
    control_id = "KVM-2.2"
    control_title = "VNC guest consoles not exposed unauthenticated"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Bind VNC to localhost in /etc/libvirt/qemu.conf:\n"
        '  vnc_listen = "127.0.0.1"\n'
        "Reach consoles via `virsh` / SSH tunnel. If network VNC is required,\n"
        "set vnc_tls = 1 (with x509 certs) or vnc_sasl = 1. Restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        vnc_listen = _conf(out, "vnc_listen")
        vnc_tls = _conf(out, "vnc_tls")
        vnc_sasl = _conf(out, "vnc_sasl")
        exposed = vnc_listen == "0.0.0.0" and vnc_tls != "1" and vnc_sasl != "1"

        verdict = "FAIL" if exposed else "PASS"
        return self._result(
            verdict, cmd, out, err, {"vnc_listen": vnc_listen, "vnc_tls": vnc_tls, "vnc_sasl": vnc_sasl}, t0, ctx
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


CHECK = _VncExposureCheck()
register_check(CHECK)
