"""IOS-2.2 — Cleartext HTTP management server disabled.

CIS Cisco Benchmark: `ip http server` exposes the device's web management
over plaintext HTTP (credentials + session in the clear). It must be disabled
(use `ip http secure-server` / SSH instead).

FAIL if `ip http server` is enabled. PASS if disabled (`no ip http server`)
or absent. ERROR if the output isn't an IOS running-config.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.cisco._common import SHOW_RUN, looks_like_ios, make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

# A line that is exactly "ip http server" (enabled) — not "no ip http server".
_HTTP_ON_RE = re.compile(r"^ip http server\b", re.IGNORECASE | re.MULTILINE)


class _HttpServerCheck:
    control_id = "IOS-2.2"
    control_title = "Cleartext HTTP management server disabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Disable the HTTP server:\n  no ip http server\nUse `ip http secure-server` (HTTPS) if web mgmt is required."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, SHOW_RUN, shell=True, timeout_s=15)
        if not looks_like_ios(out):
            return make_error(
                self, cmd=SHOW_RUN, out=out, err=err, t0=t0, ctx=ctx, reason="not an IOS running-config (Cisco host?)"
            )

        enabled = bool(_HTTP_ON_RE.search(out))
        verdict = "FAIL" if enabled else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=SHOW_RUN,
            out=out[:1024],
            err=err,
            parsed={"http_server_enabled": enabled},
            t0=t0,
            ctx=ctx,
        )


CHECK = _HttpServerCheck()
register_check(CHECK)
