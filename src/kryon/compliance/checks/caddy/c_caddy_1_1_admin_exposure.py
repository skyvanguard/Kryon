"""CADDY-1.1 — Admin API not exposed to the network.

Caddy's admin API can fully reconfigure the running server (load config, read
secrets). It binds to localhost:2019 by default. Binding it to a non-loopback
address (`admin 0.0.0.0:2019`, `admin :2019`, a public IP) turns it into a
remote takeover channel.

FAIL if the admin endpoint is bound to a non-loopback address. PASS if it is
localhost, a unix socket, `admin off`, or left at the default. ERROR if the
Caddyfile is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.caddy._common import CADDYFILE, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_ADMIN_RE = re.compile(r"^\s*admin\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_LOCAL_PREFIXES = ("localhost", "127.0.0.1", "[::1]", "unix/")


class _AdminExposureCheck:
    control_id = "CADDY-1.1"
    control_title = "Admin API not exposed to the network"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Keep the admin API local in the global options block:\n"
        "  { admin localhost:2019 }\n"
        "or `admin off` if you don't use it. Never bind it to 0.0.0.0 / a public IP."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, CADDYFILE, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=CADDYFILE, out=out, err=err, t0=t0, ctx=ctx, reason="Caddyfile unreadable (Caddy host?)"
            )

        m = _ADMIN_RE.search(uncommented(out))
        if not m:
            return make_result(
                check=self,
                verdict="PASS",
                cmd=CADDYFILE,
                out=out[:1024],
                err=err,
                parsed={"admin": "(default localhost:2019)"},
                t0=t0,
                ctx=ctx,
            )

        addr = m.group(1)
        low = addr.lower()
        exposed = low != "off" and not low.startswith(_LOCAL_PREFIXES)
        verdict = "FAIL" if exposed else "PASS"
        return make_result(
            check=self, verdict=verdict, cmd=CADDYFILE, out=out[:1024], err=err, parsed={"admin": addr}, t0=t0, ctx=ctx
        )


CHECK = _AdminExposureCheck()
register_check(CHECK)
