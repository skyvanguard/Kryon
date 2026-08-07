"""CADDY-1.2 — Automatic HTTPS not disabled.

Caddy's headline security feature is automatic HTTPS (provisions + renews
certs, redirects HTTP→HTTPS). `auto_https off` disables it entirely, serving
plaintext HTTP. It must not be globally off.

FAIL if `auto_https off` is set. PASS otherwise (default on, or a narrower
`disable_redirects` that keeps certs). ERROR if the Caddyfile is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.caddy._common import CADDYFILE, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_AUTO_HTTPS_RE = re.compile(r"^\s*auto_https\s+(\S+)", re.IGNORECASE | re.MULTILINE)


class _AutoHttpsCheck:
    control_id = "CADDY-1.2"
    control_title = "Automatic HTTPS not disabled"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Remove `auto_https off` from the global options block so Caddy provisions TLS and redirects HTTP→HTTPS."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, CADDYFILE, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=CADDYFILE, out=out, err=err, t0=t0, ctx=ctx, reason="Caddyfile unreadable (Caddy host?)"
            )

        values = {m.lower() for m in _AUTO_HTTPS_RE.findall(uncommented(out))}
        verdict = "FAIL" if "off" in values else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=CADDYFILE,
            out=out[:1024],
            err=err,
            parsed={"auto_https": sorted(values) or ["(default on)"]},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AutoHttpsCheck()
register_check(CHECK)
