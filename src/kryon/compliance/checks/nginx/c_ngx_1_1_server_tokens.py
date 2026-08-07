"""NGX-1.1 — server_tokens off (version disclosure).

CIS nginx Benchmark: with server_tokens on (the default) nginx emits its exact
version in the `Server` header and error pages, handing attackers a CVE
shortlist. It must be explicitly set off.

FAIL if any `server_tokens on` is present, or if server_tokens is never set
(default = on). PASS only when set off. ERROR if `nginx -T` can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.nginx._common import NGINX_DUMP, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_TOKENS_RE = re.compile(r"\bserver_tokens\s+(on|off)\b", re.IGNORECASE)


class _ServerTokensCheck:
    control_id = "NGX-1.1"
    control_title = "server_tokens off (version disclosure)"
    section = "1"
    severity = "LOW"
    remediation_static = "In the http block:\n  server_tokens off;\nReload: nginx -s reload"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, NGINX_DUMP, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=NGINX_DUMP, out=out, err=err, t0=t0, ctx=ctx, reason="`nginx -T` failed (nginx host?)"
            )

        values = {m.group(1).lower() for m in _TOKENS_RE.finditer(uncommented(out))}
        if "on" in values:
            verdict = "FAIL"
        elif "off" in values:
            verdict = "PASS"
        else:
            verdict = "FAIL"  # unset -> default on
        return make_result(
            check=self,
            verdict=verdict,
            cmd=NGINX_DUMP,
            out=out,
            err=err,
            parsed={"server_tokens": sorted(values) or ["(unset→on)"]},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ServerTokensCheck()
register_check(CHECK)
