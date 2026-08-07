"""ESX-6.1 — Weak TLS protocols disabled.

CIS ESXi Benchmark: `/UserVars/ESXiVPsDisabledProtocols` must disable the
deprecated transports — at minimum sslv3, tlsv1 (1.0) and tlsv1.1 — leaving
only TLS 1.2+. Read via `esxcli system settings advanced`.

FAIL if tlsv1 or tlsv1.1 is not in the disabled list. ERROR if unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MUST_DISABLE = ("tlsv1", "tlsv1.1")


def _str_value(out: str) -> str | None:
    m = re.search(r"String Value:\s*(.*)", out)
    return m.group(1).strip() if m else None


class _WeakTlsCheck:
    control_id = "ESX-6.1"
    control_title = "Weak TLS protocols (1.0/1.1) disabled"
    section = "6"
    severity = "HIGH"
    remediation_static = (
        "Disable legacy transports (leaves TLS 1.2+):\n"
        "  esxcli system settings advanced set -o /UserVars/ESXiVPsDisabledProtocols "
        "-s 'sslv3,tlsv1,tlsv1.1'\n"
        "Restart management agents (or reboot) to apply."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /UserVars/ESXiVPsDisabledProtocols"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        disabled = (_str_value(out) or "").lower()
        # tlsv1.1 contains "tlsv1" as a substring, so check tokens, not `in`.
        tokens = {t.strip() for t in re.split(r"[,\s]+", disabled) if t.strip()}
        missing = [p for p in _MUST_DISABLE if p not in tokens]

        verdict = "PASS" if not missing else "FAIL"
        return self._result(
            verdict, cmd, out, err, {"disabled_protocols": sorted(tokens), "still_enabled": missing}, t0, ctx
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


CHECK = _WeakTlsCheck()
register_check(CHECK)
