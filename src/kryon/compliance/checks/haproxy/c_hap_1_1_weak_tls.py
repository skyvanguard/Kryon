"""HAP-1.1 — Weak TLS protocols disabled on binds.

CIS/hardening: HAProxy should refuse SSLv3, TLSv1.0 and TLSv1.1. That is
expressed either as `ssl-min-ver TLSv1.2` (preferred) or the older
`no-sslv3 no-tlsv10 no-tlsv11` bind options.

FAIL if an ssl-min-ver is a weak protocol. PASS if ssl-min-ver is TLSv1.2/1.3,
or all three no-tlsv1* options are set. N/A if TLS termination has no explicit
version policy (can't judge without guessing). ERROR if the config is
unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.haproxy._common import HAPROXY_CFG, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_MINVER_RE = re.compile(r"ssl-min-ver\s+(\S+)", re.IGNORECASE)
_WEAK = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
_NO_OPTS = ("no-sslv3", "no-tlsv10", "no-tlsv11")


class _WeakTlsCheck:
    control_id = "HAP-1.1"
    control_title = "Weak TLS protocols disabled on binds"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "In global (applies to all ssl binds):\n"
        "  ssl-default-bind-options ssl-min-ver TLSv1.2\n"
        "or per bind: `bind :443 ssl crt … ssl-min-ver TLSv1.2`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, HAPROXY_CFG, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=HAPROXY_CFG, out=out, err=err, t0=t0, ctx=ctx, reason="haproxy.cfg unreadable (HAProxy host?)"
            )

        cfg = uncommented(out)
        low = cfg.lower()
        minvers = {m.lower() for m in _MINVER_RE.findall(cfg)}
        weak = sorted(minvers & _WEAK)
        if weak:
            verdict, parsed = "FAIL", {"weak_ssl_min_ver": weak}
        elif minvers:
            verdict, parsed = "PASS", {"ssl_min_ver": sorted(minvers)}
        elif all(opt in low for opt in _NO_OPTS):
            verdict, parsed = "PASS", {"no_tls1x_options": True}
        else:
            verdict, parsed = "N/A", {"reason": "no explicit TLS version policy (ssl-min-ver / no-tlsv1* absent)"}
        return make_result(
            check=self, verdict=verdict, cmd=HAPROXY_CFG, out=out[:1024], err=err, parsed=parsed, t0=t0, ctx=ctx
        )


CHECK = _WeakTlsCheck()
register_check(CHECK)
