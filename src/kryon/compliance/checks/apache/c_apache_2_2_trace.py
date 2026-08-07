"""APACHE-2.2 — TraceEnable Off.

CIS Apache Benchmark: the HTTP TRACE method echoes the request back and
enables Cross-Site Tracing (XST), letting script steal HttpOnly cookies /
auth headers. `TraceEnable` defaults to On and must be set Off.

FAIL if TraceEnable is On or unset (default On). PASS only when Off. ERROR if
Apache is not installed on the host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.apache._common import apache_grep, make_error, make_result, split_probe
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _TraceEnableCheck:
    control_id = "APACHE-2.2"
    control_title = "TraceEnable Off"
    section = "2"
    severity = "MEDIUM"
    remediation_static = "In the global config:\n  TraceEnable Off\nThen reload Apache."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = apache_grep(r"^[[:space:]]*TraceEnable[[:space:]]")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        present, lines = split_probe(out)
        if not present:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="Apache config not found (Apache host?)"
            )

        value = lines[-1].split()[1].lower() if lines else "(unset→on)"
        verdict = "PASS" if value == "off" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"trace_enable": value}, t0=t0, ctx=ctx
        )


CHECK = _TraceEnableCheck()
register_check(CHECK)
