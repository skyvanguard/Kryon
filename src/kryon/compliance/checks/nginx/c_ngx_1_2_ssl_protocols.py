"""NGX-1.2 — Weak TLS/SSL protocols disabled.

CIS nginx Benchmark: SSLv2, SSLv3, TLSv1.0 and TLSv1.1 are deprecated and
broken (POODLE, BEAST). `ssl_protocols` must list only TLSv1.2 / TLSv1.3.

FAIL if ssl_protocols includes any weak protocol. N/A if no ssl_protocols
directive exists (TLS not terminated here — nothing to assess without
guessing). ERROR if `nginx -T` can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.nginx._common import NGINX_DUMP, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_SSL_PROTO_RE = re.compile(r"\bssl_protocols\s+([^;]+);", re.IGNORECASE)
_WEAK = {"sslv2", "sslv3", "tlsv1", "tlsv1.1"}


class _SslProtocolsCheck:
    control_id = "NGX-1.2"
    control_title = "Weak TLS/SSL protocols disabled"
    section = "1"
    severity = "HIGH"
    remediation_static = "In the http/server block:\n  ssl_protocols TLSv1.2 TLSv1.3;\nReload: nginx -s reload"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, NGINX_DUMP, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=NGINX_DUMP, out=out, err=err, t0=t0, ctx=ctx, reason="`nginx -T` failed (nginx host?)"
            )

        matches = _SSL_PROTO_RE.findall(uncommented(out))
        if not matches:
            return make_result(
                check=self,
                verdict="N/A",
                cmd=NGINX_DUMP,
                out=out,
                err=err,
                parsed={"reason": "no ssl_protocols directive (no TLS terminated here)"},
                t0=t0,
                ctx=ctx,
            )

        tokens = {t.lower() for line in matches for t in line.split()}
        weak = sorted(_WEAK & tokens)
        verdict = "FAIL" if weak else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=NGINX_DUMP,
            out=out,
            err=err,
            parsed={"weak_protocols": weak, "configured": sorted(tokens)},
            t0=t0,
            ctx=ctx,
        )


CHECK = _SslProtocolsCheck()
register_check(CHECK)
