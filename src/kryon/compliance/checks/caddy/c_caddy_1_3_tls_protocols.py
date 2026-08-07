"""CADDY-1.3 — Weak TLS versions not allowed.

Caddy floors TLS at 1.2 by default. A `protocols` directive inside a `tls`
block can lower that (`protocols tls1.0 tls1.3`), re-enabling the broken
TLS 1.0 / 1.1.

FAIL if a protocols directive allows tls1.0 or tls1.1. PASS if it lists only
tls1.2/tls1.3, or is absent (secure default). ERROR if the Caddyfile is
unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.caddy._common import CADDYFILE, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_PROTOCOLS_RE = re.compile(r"^\s*protocols\s+([^\n}]+)", re.IGNORECASE | re.MULTILINE)
_WEAK = {"tls1.0", "tls1.1"}


class _TlsProtocolsCheck:
    control_id = "CADDY-1.3"
    control_title = "Weak TLS versions not allowed"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Remove any `protocols` line that lowers the floor, or set:\n"
        "  tls { protocols tls1.2 tls1.3 }\n"
        "Caddy already defaults to a TLS 1.2 minimum."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, CADDYFILE, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=CADDYFILE, out=out, err=err, t0=t0, ctx=ctx, reason="Caddyfile unreadable (Caddy host?)"
            )

        tokens = {t.lower() for line in _PROTOCOLS_RE.findall(uncommented(out)) for t in line.split()}
        weak = sorted(tokens & _WEAK)
        verdict = "FAIL" if weak else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=CADDYFILE,
            out=out[:1024],
            err=err,
            parsed={"weak_protocols": weak},
            t0=t0,
            ctx=ctx,
        )


CHECK = _TlsProtocolsCheck()
register_check(CHECK)
