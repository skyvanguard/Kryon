"""KVM-2.3 — SPICE guest consoles are not exposed unauthenticated.

Like VNC (KVM-2.2), the SPICE console gives full keyboard/screen/USB access
to a guest. /etc/libvirt/qemu.conf `spice_listen` should bind to localhost
(127.0.0.1); if bound to 0.0.0.0 it must require TLS or SASL.

FAIL if spice_listen = "0.0.0.0" AND neither spice_tls=1 nor spice_sasl=1.
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


class _SpiceExposureCheck:
    control_id = "KVM-2.3"
    control_title = "SPICE guest consoles not exposed unauthenticated"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Bind SPICE to localhost in /etc/libvirt/qemu.conf:\n"
        '  spice_listen = "127.0.0.1"\n'
        "Reach consoles via `virsh` / SSH tunnel. If network SPICE is required,\n"
        "set spice_tls = 1 (with x509 certs) or spice_sasl = 1. Restart libvirtd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/libvirt/qemu.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read qemu.conf"}, t0, ctx)

        spice_listen = _conf(out, "spice_listen")
        spice_tls = _conf(out, "spice_tls")
        spice_sasl = _conf(out, "spice_sasl")
        exposed = spice_listen == "0.0.0.0" and spice_tls != "1" and spice_sasl != "1"

        verdict = "FAIL" if exposed else "PASS"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"spice_listen": spice_listen, "spice_tls": spice_tls, "spice_sasl": spice_sasl},
            t0,
            ctx,
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


CHECK = _SpiceExposureCheck()
register_check(CHECK)
