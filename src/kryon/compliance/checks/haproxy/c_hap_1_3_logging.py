"""HAP-1.3 — Logging configured.

Without a `log` directive HAProxy emits no access/event logs, so there is no
audit trail of connections, errors or attacks reaching the backends.

FAIL if no `log` directive is present. PASS if one is. ERROR if the config is
unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.haproxy._common import HAPROXY_CFG, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

# `log <target>` — note the required whitespace excludes log-format / log-tag.
_LOG_RE = re.compile(r"^\s*log\s+\S+", re.IGNORECASE | re.MULTILINE)


class _LoggingCheck:
    control_id = "HAP-1.3"
    control_title = "Logging configured"
    section = "1"
    severity = "LOW"
    remediation_static = (
        "Add a log target in global and reference it in defaults:\n"
        "  global\n    log /dev/log local0\n  defaults\n    log global\n    option httplog"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, HAPROXY_CFG, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=HAPROXY_CFG, out=out, err=err, t0=t0, ctx=ctx, reason="haproxy.cfg unreadable (HAProxy host?)"
            )

        has_log = bool(_LOG_RE.search(uncommented(out)))
        verdict = "PASS" if has_log else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=HAPROXY_CFG,
            out=out[:1024],
            err=err,
            parsed={"log_directive": has_log},
            t0=t0,
            ctx=ctx,
        )


CHECK = _LoggingCheck()
register_check(CHECK)
