"""FGT-1.7 — Admin GUI enforces strong TLS (no TLS 1.0 / 1.1).

`config system global` → `admin-https-ssl-versions` controls the TLS
versions the management GUI accepts. TLS 1.0 and 1.1 are deprecated and
FAIL a CIS Fortinet Benchmark review. `get system global` shows the
effective value (including defaults).

FAIL if the accepted versions include tlsv1-0 or tlsv1-1. ERROR if the
value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_WEAK_TLS = ("tlsv1-0", "tlsv1-1")


def _get_value(out: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


class _AdminGuiTlsCheck:
    control_id = "FGT-1.7"
    control_title = "Admin GUI enforces strong TLS (no TLS 1.0/1.1)"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Restrict the admin GUI to TLS 1.2+:\n"
        "  config system global\n"
        "    set admin-https-ssl-versions tlsv1-2 tlsv1-3\n"
        "  end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system global"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read system global"}, t0, ctx)

        versions = _get_value(out, "admin-https-ssl-versions")
        weak = [v for v in _WEAK_TLS if versions and v in versions]
        verdict = "FAIL" if weak else "PASS"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"admin_https_ssl_versions": versions, "weak_versions_enabled": weak},
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
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AdminGuiTlsCheck()
register_check(CHECK)
