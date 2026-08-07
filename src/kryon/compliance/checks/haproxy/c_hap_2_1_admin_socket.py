"""HAP-2.1 — Runtime admin socket not exposed over TCP.

The HAProxy runtime API (`stats socket`) can drain servers, change weights and
read state. Bound to a unix socket it is local-only; bound to a TCP address
(ipv4@/ipv6@/tcp@) it becomes a network-reachable admin channel — often with
`level admin`.

FAIL if any stats socket is bound to a TCP address. PASS if all are unix
sockets. N/A if there is no runtime socket. ERROR if the config is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.haproxy._common import HAPROXY_CFG, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_SOCKET_RE = re.compile(r"^\s*stats\s+socket\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_TCP_PREFIXES = ("ipv4@", "ipv6@", "tcp@", "tcp4@", "tcp6@")


class _AdminSocketCheck:
    control_id = "HAP-2.1"
    control_title = "Runtime admin socket not exposed over TCP"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Bind the runtime API to a unix socket, not TCP:\n"
        "  stats socket /run/haproxy/admin.sock mode 660 level admin\n"
        "If TCP is unavoidable, restrict it with an ACL and mTLS."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, HAPROXY_CFG, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=HAPROXY_CFG, out=out, err=err, t0=t0, ctx=ctx, reason="haproxy.cfg unreadable (HAProxy host?)"
            )

        sockets = _SOCKET_RE.findall(uncommented(out))
        if not sockets:
            return make_result(
                check=self,
                verdict="N/A",
                cmd=HAPROXY_CFG,
                out=out[:1024],
                err=err,
                parsed={"reason": "no runtime stats socket"},
                t0=t0,
                ctx=ctx,
            )

        tcp = sorted(s for s in sockets if s.lower().startswith(_TCP_PREFIXES))
        verdict = "FAIL" if tcp else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=HAPROXY_CFG,
            out=out[:1024],
            err=err,
            parsed={"tcp_sockets": tcp},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AdminSocketCheck()
register_check(CHECK)
