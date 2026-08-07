"""HAP-1.2 — Stats page requires authentication.

The HAProxy stats page (`stats enable` / `stats uri`) exposes backend
topology, health and traffic, and can allow admin actions. If it is enabled
it must be protected with `stats auth` (or an equivalent http-request auth).

FAIL if stats is enabled anywhere and no stats auth directive exists at all.
PASS if stats auth is present. N/A if the stats page isn't enabled. ERROR if
the config is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.haproxy._common import HAPROXY_CFG, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_STATS_ON_RE = re.compile(r"^\s*stats\s+(enable|uri)\b", re.IGNORECASE | re.MULTILINE)
_STATS_AUTH_RE = re.compile(r"^\s*stats\s+(auth|http-request)\b", re.IGNORECASE | re.MULTILINE)


class _StatsAuthCheck:
    control_id = "HAP-1.2"
    control_title = "Stats page requires authentication"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Protect the stats listener:\n"
        "  stats auth <user>:<strong-password>\n"
        "or bind it to localhost / an ACL-restricted frontend."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, HAPROXY_CFG, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=HAPROXY_CFG, out=out, err=err, t0=t0, ctx=ctx, reason="haproxy.cfg unreadable (HAProxy host?)"
            )

        cfg = uncommented(out)
        if not _STATS_ON_RE.search(cfg):
            return make_result(
                check=self,
                verdict="N/A",
                cmd=HAPROXY_CFG,
                out=out[:1024],
                err=err,
                parsed={"reason": "stats page not enabled"},
                t0=t0,
                ctx=ctx,
            )

        has_auth = bool(_STATS_AUTH_RE.search(cfg))
        verdict = "PASS" if has_auth else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=HAPROXY_CFG,
            out=out[:1024],
            err=err,
            parsed={"stats_auth": has_auth},
            t0=t0,
            ctx=ctx,
        )


CHECK = _StatsAuthCheck()
register_check(CHECK)
